/*
 * Copyright 2015-2016 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2
 *
 * Homepage:
 * https://github.com/ephox-gcc-plugins/initify
 *
 * This plugin has two passes. The first one tries to find all functions that
 * can be become __init/__exit. The second one moves string constants
 * (local variables and function string arguments marked by
 * the nocapture attribute) only referenced in __init/__exit functions
 * to __initconst/__exitconst sections.
 * Based on an idea from Mathias Krause <minipli@ld-linux.so>.
 *
 * The instrumentation pass of the latent_entropy plugin must run after
 * the initify plugin to increase coverage.
 *
 * Options:
 * -fplugin-arg-initify_plugin-disable
 * -fplugin-arg-initify_plugin-verbose
 * -fplugin-arg-initify_plugin-print_missing_attr
 * -fplugin-arg-initify_plugin-search_init_exit_functions
 *
 * Attribute: __attribute__((nocapture(x, y ...)))
 *  The nocapture gcc attribute can be on functions only.
 *  The attribute takes one or more unsigned integer constants as parameters
 *  that specify the function argument(s) of const char* type to initify.
 *  If the marked argument is a vararg then the plugin initifies
 *  all vararg arguments.
 *
 * Usage:
 * $ make
 * $ make run
 */

#include "gcc-common.h"

int plugin_is_GPL_compatible;

static struct plugin_info initify_plugin_info = {
	.version	=	"20160629vanilla",
	.help		=	"disable\tturn off the initify plugin\n"
				 "verbose\tprint all initified strings and all"
				 " functions which should be __init/__exit\n"
				 "print_missing_attr\tprint functions which"
				 " can be marked by nocapture attribute\n"
				 "search_init_exit_functions\tsearch function"
				 " which should be marked by __init or __exit"
				 " attribute\n"
};

static struct cgraph_2node_hook_list *node_duplication_hook_holder;
#define ARGNUM_NONE 0
static bool verbose, print_missing_attr, search_init_exit_functions;

enum section_type {
	INIT, EXIT, NONE
};

#if BUILDING_GCC_VERSION >= 5000
typedef struct hash_set<const_gimple> gimple_set;

static inline bool pointer_set_insert(gimple_set *visited, const_gimple stmt)
{
	return visited->add(stmt);
}

static inline bool pointer_set_contains(gimple_set *visited, const_gimple stmt)
{
	return visited->contains(stmt);
}

static inline gimple_set* pointer_set_create(void)
{
	return new hash_set<const_gimple>;
}

static inline void pointer_set_destroy(gimple_set *visited)
{
	delete visited;
}
#else
typedef struct pointer_set_t gimple_set;
#endif

static void walk_def_stmt(bool *has_str_cst, gimple_set *visited, tree node);

/* nocapture attribute:
 *  * to mark nocapture function arguments. If used on a vararg argument
 *    it applies to all of them that have no other uses.
 *  * attribute value 0 is ignored to allow reusing print attribute arguments
 */
static tree handle_nocapture_attribute(tree *node, tree __unused name,
					tree args, int __unused flags,
					bool *no_add_attrs)
{
	tree orig_attr, arg;

	*no_add_attrs = true;
	switch (TREE_CODE(*node)) {
	case FUNCTION_DECL:
	case FUNCTION_TYPE:
	case METHOD_TYPE:
		break;

	case TYPE_DECL: {
		enum tree_code fn_code;
		const_tree fntype = TREE_TYPE(*node);

		fn_code = TREE_CODE(fntype);
		if (fn_code == POINTER_TYPE)
			fntype = TREE_TYPE(fntype);
		fn_code = TREE_CODE(fntype);
		if (fn_code == FUNCTION_TYPE || fn_code == METHOD_TYPE)
			break;
		/* FALLTHROUGH */
	}

	default:
		debug_tree(*node);
		error("%s: %qE attribute only applies to functions",
			__func__, name);
		return NULL_TREE;
	}

	for (arg = args; arg; arg = TREE_CHAIN(arg)) {
		tree position = TREE_VALUE(arg);

		if (TREE_CODE(position) != INTEGER_CST) {
			error("%qE parameter of the %qE attribute isn't an integer (fn: %qE)",
				position, name, *node);
			return NULL_TREE;
		}

		if (tree_int_cst_lt(position, integer_minus_one_node)) {
			error("%qE parameter of the %qE attribute less than 0 (fn: %qE)",
				position, name, *node);
			return NULL_TREE;
		}
	}

	orig_attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(*node));
	if (orig_attr)
		chainon(TREE_VALUE(orig_attr), args);
	else
		*no_add_attrs = false;

	return NULL_TREE;
}

static struct attribute_spec nocapture_attr = {
	.name				= "nocapture",
	.min_length			= 1,
	.max_length			= -1,
	.decl_required			= true,
	.type_required			= false,
	.function_type_required		= false,
	.handler			= handle_nocapture_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
};

static void register_attributes(void __unused *event_data, void __unused *data)
{
	register_attribute(&nocapture_attr);
}

/* Determine whether the function is in the init or exit sections. */
static enum section_type get_init_exit_section(const_tree decl)
{
	const char *str;
	const_tree section, attr_value;

	section = lookup_attribute("section", DECL_ATTRIBUTES(decl));
	if (!section)
		return NONE;

	attr_value = TREE_VALUE(section);
	gcc_assert(attr_value != NULL_TREE);
	gcc_assert(list_length(attr_value) == 1);

	str = TREE_STRING_POINTER(TREE_VALUE(attr_value));

	if (!strncmp(str, ".init.", 6))
		return INIT;
	if (!strncmp(str, ".exit.", 6))
		return EXIT;
	return NONE;
}

static tree get_string_cst(tree var)
{
	if (var == NULL_TREE)
		return NULL_TREE;

	if (TREE_CODE(var) == STRING_CST)
		return var;

	switch (TREE_CODE_CLASS(TREE_CODE(var))) {
	case tcc_expression:
	case tcc_reference: {
		int i;

		for (i = 0; i < TREE_OPERAND_LENGTH(var); i++) {
			tree ret = get_string_cst(TREE_OPERAND(var, i));
			if (ret != NULL_TREE)
				return ret;
		}
		break;
	}

	default:
		break;
	}

	return NULL_TREE;
}

static bool set_init_exit_section(tree decl)
{
	gcc_assert(DECL_P(decl));

	if (get_init_exit_section(decl) != NONE)
		return false;

	if (get_init_exit_section(current_function_decl) == INIT)
		set_decl_section_name(decl, ".init.rodata.str");
	else
		set_decl_section_name(decl, ".exit.rodata.str");
	return true;
}

/* Syscalls are always nocapture functions. */
static bool is_syscall(const_tree fn)
{
	if (!strncmp(DECL_NAME_POINTER(fn), "sys_", 4))
		return true;

	if (!strncmp(DECL_NAME_POINTER(fn), "sys32_", 6))
		return true;

	if (!strncmp(DECL_NAME_POINTER(fn), "compat_sys_", 11))
		return true;

	return false;
}

static bool is_nocapture_param(const_tree fndecl, int fn_arg_count)
{
	const_tree attr, attr_val;
	int fntype_arg_len;

	if (is_syscall(fndecl))
		return true;

	fntype_arg_len = type_num_arguments(TREE_TYPE(fndecl));
	attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(fndecl));
	if (attr == NULL_TREE)
		return false;

	for (attr_val = TREE_VALUE(attr); attr_val;
		attr_val = TREE_CHAIN(attr_val)) {
		int attr_arg_val = (int)tree_to_shwi(TREE_VALUE(attr_val));

		if (attr_arg_val == -1)
			return true;
		if (attr_arg_val == fn_arg_count)
			return true;
		if (attr_arg_val > fntype_arg_len &&
					fn_arg_count >= attr_arg_val)
			return true;
	}

	return false;
}

static bool is_same_vardecl(const_tree op, const_tree vardecl)
{
	const_tree decl;

	if (op == vardecl)
		return true;
	if (TREE_CODE(op) == SSA_NAME)
		decl = SSA_NAME_VAR(op);
	else
		decl = op;
	if (decl == NULL_TREE || !DECL_P(decl))
		return false;

	return DECL_NAME(decl) &&
		!strcmp(DECL_NAME_POINTER(decl), DECL_NAME_POINTER(vardecl));
}

static bool search_same_vardecl(const_tree value, const_tree vardecl)
{
	int i;

	for (i = 0; i < TREE_OPERAND_LENGTH(value); i++) {
		const_tree op = TREE_OPERAND(value, i);

		if (op == NULL_TREE)
			continue;
		if (is_same_vardecl(op, vardecl))
			return true;
		if (search_same_vardecl(op, vardecl))
			return true;
	}
	return false;
}

static bool check_constructor(const_tree constructor, const_tree vardecl)
{
	unsigned HOST_WIDE_INT cnt __unused;
	tree value;

	FOR_EACH_CONSTRUCTOR_VALUE(CONSTRUCTOR_ELTS(constructor), cnt, value) {
		if (TREE_CODE(value) == CONSTRUCTOR)
			return check_constructor(value, vardecl);
		if (is_gimple_constant(value))
			continue;

		gcc_assert(TREE_OPERAND_LENGTH(value) > 0);
		if (search_same_vardecl(value, vardecl))
			return true;
	}
	return false;
}

static bool compare_ops(const_tree vardecl, tree op)
{
	if (TREE_CODE(op) == TREE_LIST)
		op = TREE_VALUE(op);
	if (TREE_CODE(op) == SSA_NAME)
		op = SSA_NAME_VAR(op);
	if (op == NULL_TREE)
		return false;

	switch (TREE_CODE_CLASS(TREE_CODE(op))) {
	case tcc_declaration:
		return is_same_vardecl(op, vardecl);

	case tcc_exceptional:
		return check_constructor(op, vardecl);

	case tcc_constant:
	case tcc_statement:
	case tcc_comparison:
		return false;

	default:
		break;
	}

	gcc_assert(TREE_OPERAND_LENGTH(op) > 0);
	return search_same_vardecl(op, vardecl);
}

static bool search_capture_use(const_tree vardecl, gimple stmt)
{
	unsigned int i;

	for (i = 0; i < gimple_num_ops(stmt); i++) {
		unsigned int arg_count;
		const_tree fndecl, arg;
		tree op = *(gimple_op_ptr(stmt, i));

		if (op == NULL_TREE)
			continue;
		if (is_gimple_constant(op))
			continue;

		if (!compare_ops(vardecl, op))
			continue;

		if (!is_gimple_call(stmt))
			return true;

		/* return, fndecl */
		gcc_assert(i >= 3);
		arg_count = i - 2;

		arg = gimple_call_arg(stmt, arg_count - 1);
		gcc_assert(TREE_CODE(TREE_TYPE(arg)) == POINTER_TYPE);

		fndecl = gimple_call_fndecl(stmt);
		if (is_nocapture_param(fndecl, (int)arg_count))
			continue;

		gcc_assert(fndecl != NULL_TREE);

		/*
		 * These are potentially nocapture functions that must be
		 * checked manually.
		 */
		if (print_missing_attr)
			inform(gimple_location(stmt), "nocapture attribute is missing (fn: %E, arg: %u)\n",
							fndecl, arg_count);
		return true;

	}
	return false;
}

static bool is_in_capture_init(const_tree vardecl)
{
	unsigned int i __unused;
	tree var;

	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		const_tree initial = DECL_INITIAL(var);

		if (DECL_EXTERNAL(var))
			continue;
		if (initial == NULL_TREE)
			continue;
		if (TREE_CODE(initial) != CONSTRUCTOR)
			continue;

		gcc_assert(TREE_CODE(TREE_TYPE(var)) == RECORD_TYPE ||
								DECL_P(var));
		if (check_constructor(initial, vardecl))
			return true;
	}
	return false;
}

static bool has_capture_use_local_var(const_tree vardecl)
{
	basic_block bb;

	if (is_in_capture_init(vardecl))
		return true;

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			if (search_capture_use(vardecl, gsi_stmt(gsi)))
				return true;
		}
	}

	return false;
}

/* Search local variables that have only nocapture uses. */
static void find_local_str(void)
{
	unsigned int i __unused;
	tree var;

	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		tree str, init_val;

		if (TREE_CODE(TREE_TYPE(var)) != ARRAY_TYPE)
			continue;

		init_val = DECL_INITIAL(var);
		if (init_val == NULL_TREE || init_val == error_mark_node)
			continue;
		if (TREE_CODE(init_val) != STRING_CST)
			continue;

		if (has_capture_use_local_var(var))
			continue;

		str = get_string_cst(init_val);
		gcc_assert(str);

		if (set_init_exit_section(var) && verbose)
			inform(DECL_SOURCE_LOCATION(var), "initified local var: %s: %s",
				DECL_NAME_POINTER(current_function_decl),
				TREE_STRING_POINTER(str));
	}
}

static tree create_decl(tree node)
{
	tree str, decl, type, name;
	location_t loc = DECL_SOURCE_LOCATION(current_function_decl);

	str = get_string_cst(node);
	type = TREE_TYPE(str);
	gcc_assert(TREE_CODE(type) == ARRAY_TYPE);
	gcc_assert(TREE_TYPE(type) != NULL_TREE &&
			TREE_CODE(TREE_TYPE(type)) == INTEGER_TYPE);
	name = create_tmp_var_name("initify");
	decl = build_decl(loc, VAR_DECL, name, type);

	DECL_INITIAL(decl) = str;
	DECL_CONTEXT(decl) = current_function_decl;
	DECL_ARTIFICIAL(decl) = 1;

	TREE_STATIC(decl) = 1;
	TREE_READONLY(decl) = 1;
	TREE_ADDRESSABLE(decl) = 1;
	TREE_USED(decl) = 1;

	add_referenced_var(decl);
	add_local_decl(cfun, decl);

	varpool_add_new_variable(decl);
	varpool_mark_needed_node(varpool_node(decl));

	DECL_CHAIN(decl) = BLOCK_VARS(DECL_INITIAL(current_function_decl));
	BLOCK_VARS(DECL_INITIAL(current_function_decl)) = decl;

	return build_fold_addr_expr_loc(loc, decl);
}

static void set_section_call_assign(gimple stmt, tree node, unsigned int num)
{
	tree decl;

	decl = create_decl(node);

	switch (gimple_code(stmt)) {
	case GIMPLE_ASSIGN:
		gcc_assert(gimple_num_ops(stmt) == 2);
		gimple_assign_set_rhs1(stmt, decl);
		break;

	case GIMPLE_CALL:
		gimple_call_set_arg(stmt, num, decl);
		break;

	default:
		debug_gimple_stmt(stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}

	update_stmt(stmt);

	if (set_init_exit_section(TREE_OPERAND(decl, 0)) && verbose)
		inform(gimple_location(stmt), "initified function arg: %E: [%E]",
				current_function_decl, get_string_cst(node));
}

static tree initify_create_new_var(tree type)
{
	tree new_var = create_tmp_var(type, "initify");

	add_referenced_var(new_var);
	mark_sym_for_renaming(new_var);
	return new_var;
}

static void initify_create_new_phi_arg(tree ssa_var, gphi *stmt, unsigned int i)
{
	gassign *assign;
	gimple_stmt_iterator gsi;
	basic_block arg_bb;
	tree decl, arg;

	arg = gimple_phi_arg_def(stmt, i);
	decl = create_decl(arg);

	assign = gimple_build_assign(ssa_var, decl);

	arg_bb = gimple_phi_arg_edge(stmt, i)->src;
	gcc_assert(arg_bb->index != 0);

	gsi = gsi_after_labels(arg_bb);
	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	if (set_init_exit_section(TREE_OPERAND(decl, 0)) && verbose)
		inform(gimple_location(stmt), "initified local var, phi arg: %E: [%E]",
			current_function_decl, get_string_cst(arg));
}

static void set_section_phi(bool *has_str_cst, gimple_set *visited, gphi *stmt)
{
	tree result, ssa_var;
	unsigned int i;

	result = gimple_phi_result(stmt);
	ssa_var = initify_create_new_var(TREE_TYPE(result));

	for (i = 0; i < gimple_phi_num_args(stmt); i++) {
		tree arg = gimple_phi_arg_def(stmt, i);

		if (get_string_cst(arg) == NULL_TREE)
			walk_def_stmt(has_str_cst, visited, arg);
		else
			initify_create_new_phi_arg(ssa_var, stmt, i);
	}
}

static void walk_def_stmt(bool *has_str_cst, gimple_set *visited, tree node)
{
	gimple def_stmt;
	const_tree parm_decl;

	if (!*has_str_cst)
		return;

	if (TREE_CODE(node) != SSA_NAME) {
		*has_str_cst = false;
		return;
	}

	parm_decl = SSA_NAME_VAR(node);
	if (parm_decl != NULL_TREE && TREE_CODE(parm_decl) == PARM_DECL) {
		*has_str_cst = false;
		return;
	}

	def_stmt = SSA_NAME_DEF_STMT(node);
	if (pointer_set_insert(visited, def_stmt))
		return;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
	case GIMPLE_CALL:
	case GIMPLE_ASM:
	case GIMPLE_RETURN:
		*has_str_cst = false;
		return;

	case GIMPLE_PHI:
		set_section_phi(has_str_cst, visited, as_a_gphi(def_stmt));
		return;

	case GIMPLE_ASSIGN: {
		tree rhs1, str;

		if (gimple_num_ops(def_stmt) != 2)
			return;

		rhs1 = gimple_assign_rhs1(def_stmt);
		walk_def_stmt(has_str_cst, visited, rhs1);
		if (!*has_str_cst)
			return;
		str = get_string_cst(rhs1);
		if (str != NULL_TREE)
			set_section_call_assign(def_stmt, rhs1, 0);
		return;
	}

	default:
		debug_gimple_stmt(def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

/* Search constant strings assigned to variables. */
static void search_var_param(gcall *stmt)
{
	unsigned int num;

	for (num = 0; num < gimple_call_num_args(stmt); num++) {
		gimple_set *visited;
		const_tree type, fndecl;
		bool has_str_cst = true;
		tree str, arg = gimple_call_arg(stmt, num);

		str = get_string_cst(arg);
		if (str != NULL_TREE)
			continue;

		if (TREE_CODE(TREE_TYPE(arg)) != POINTER_TYPE)
			continue;
		type = TREE_TYPE(TREE_TYPE(arg));
		if (!TYPE_STRING_FLAG(type))
			continue;
		fndecl = gimple_call_fndecl(stmt);
		if (!is_nocapture_param(fndecl, num + 1))
			continue;

		visited = pointer_set_create();
		walk_def_stmt(&has_str_cst, visited, arg);
		pointer_set_destroy(visited);
	}
}

/* Search constant strings passed as arguments. */
static void search_str_param(gcall *stmt)
{
	unsigned int num;

	for (num = 0; num < gimple_call_num_args(stmt); num++) {
		const_tree fndecl;
		tree str, arg = gimple_call_arg(stmt, num);

		str = get_string_cst(arg);
		if (str == NULL_TREE)
			continue;

		fndecl = gimple_call_fndecl(stmt);
		if (is_nocapture_param(fndecl, num + 1))
			set_section_call_assign(stmt, arg, num);
	}
}

static bool has_nocapture_param(const_tree fndecl)
{
	const_tree attr;

	if (fndecl == NULL_TREE)
		return false;

	if (is_syscall(fndecl))
		return true;

	attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(fndecl));
	return attr != NULL_TREE;
}

/* Search constant strings in arguments of nocapture functions. */
static void search_const_strs(void)
{
	basic_block bb;

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gcall *call_stmt;
			gimple stmt = gsi_stmt(gsi);

			if (!is_gimple_call(stmt))
				continue;

			call_stmt = as_a_gcall(stmt);
			if (!has_nocapture_param(gimple_call_fndecl(call_stmt)))
				continue;
			search_str_param(call_stmt);
			search_var_param(call_stmt);
		}
	}
}

/*
 * Find and move constant strings to the proper init or exit read-only
 * data section.
 */
static unsigned int initify_execute(void)
{
	if (get_init_exit_section(current_function_decl) == NONE)
		return 0;

	find_local_str();
	search_const_strs();

	return 0;
}

#define PASS_NAME initify
#define NO_GATE
#define TODO_FLAGS_FINISH	TODO_dump_func | TODO_verify_ssa | \
				TODO_verify_stmts | \
				TODO_remove_unused_locals | \
				TODO_cleanup_cfg | TODO_ggc_collect | \
				TODO_verify_flow | TODO_update_ssa

#include "gcc-generate-gimple-pass.h"

static bool search_init_functions_gate(void)
{
	return search_init_exit_functions;
}

/*
 * If the function is called by only __init/__exit functions then it can become
 * an __init/__exit function as well.
 */
static bool should_init_exit(struct cgraph_node *callee)
{
	struct cgraph_edge *e;
	bool only_init_callers;
	const_tree callee_decl = NODE_DECL(callee);

	if (NODE_SYMBOL(callee)->aux != (void *)NONE)
		return false;
	if (get_init_exit_section(callee_decl) != NONE)
		return false;

	/* If gcc isn't in LTO mode then we can handle only static functions. */
	if (!in_lto_p && TREE_PUBLIC(callee_decl))
		return false;

	if (NODE_SYMBOL(callee)->address_taken)
		return false;

	e = callee->callers;
	if (!e)
		return false;

	only_init_callers = true;
	for (; e; e = e->next_caller) {
		enum section_type caller_section;
		struct cgraph_node *caller = e->caller;

		caller_section = get_init_exit_section(NODE_DECL(caller));
		if (caller_section == NONE &&
			NODE_SYMBOL(caller)->aux == (void *)NONE)
			only_init_callers = false;
	}

	return only_init_callers;
}

static bool inherit_section(struct cgraph_node *callee,
				struct cgraph_node *caller,
				enum section_type curfn_section)
{
	if (curfn_section == NONE)
		curfn_section = (enum section_type)(unsigned long)
					NODE_SYMBOL(caller)->aux;

	if (curfn_section == EXIT && NODE_SYMBOL(callee)->aux == (void *)INIT)
		goto set_section;

	if (!should_init_exit(callee))
		return false;

	gcc_assert(NODE_SYMBOL(callee)->aux == (void *)NONE);

set_section:
	NODE_SYMBOL(callee)->aux = (void *)curfn_section;
	return true;
}

/*
 * Try to propagate __init/__exit to callees in __init/__exit functions.
 * If a function is called by __init and __exit functions as well then it can be
 * an __exit function at most.
 */
static bool search_init_exit_callers(void)
{
	struct cgraph_node *node;
	bool change = false;

	FOR_EACH_FUNCTION(node) {
		struct cgraph_edge *e;
		enum section_type section;
		const_tree cur_fndecl = NODE_DECL(node);

		if (DECL_BUILT_IN(cur_fndecl))
			continue;

		section = get_init_exit_section(cur_fndecl);
		if (section == NONE && NODE_SYMBOL(node)->aux == (void *)NONE)
			continue;

		for (e = node->callees; e; e = e->next_callee) {
			if (e->callee->global.inlined_to)
				continue;
			if (inherit_section(e->callee, node, section))
				change = true;
		}
	}

	return change;
}

/* We can't move functions to the init/exit sections from certain sections. */
static bool can_move_to_init_exit(const_tree fndecl)
{
	const char *section_name = get_decl_section_name(fndecl);

	if (!section_name)
		return true;

	if (!strcmp(section_name, ".ref.text\000"))
		return true;

	if (!strcmp(section_name, ".meminit.text\000"))
		return false;

	inform(DECL_SOURCE_LOCATION(fndecl), "Section of %qE: %s\n",
						fndecl, section_name);
	gcc_unreachable();
}

static void move_function_to_init_exit_text(struct cgraph_node *node)
{
	const char *section_name;
	tree id, attr;
	tree section_str, attr_args, fndecl = NODE_DECL(node);

	if (NODE_SYMBOL(node)->aux == (void *)NONE)
		return;

	if (!can_move_to_init_exit(fndecl))
		return;

	if (verbose) {
		const char *attr_name;
		location_t loc = DECL_SOURCE_LOCATION(fndecl);

		attr_name = NODE_SYMBOL(node)->aux ==
					(void *)INIT ? "__init" : "__exit";

		if (in_lto_p && TREE_PUBLIC(fndecl))
			inform(loc, "%s attribute is missing from the %qE function (public)",
							attr_name, fndecl);

		if (!in_lto_p && !TREE_PUBLIC(fndecl))
			inform(loc, "%s attribute is missing from the %qE function (static)",
							attr_name, fndecl);
	}

	if (in_lto_p)
		return;

	/* Add the init/exit section attribute to the function declaration. */
	DECL_ATTRIBUTES(fndecl) = copy_list(DECL_ATTRIBUTES(fndecl));

	section_name = NODE_SYMBOL(node)->aux ==
				(void *)INIT ? ".init.text" : ".exit.text";
	section_str = build_string(strlen(section_name) + 1, section_name);
	TREE_READONLY(section_str) = 1;
	TREE_STATIC(section_str) = 1;
	attr_args = build_tree_list(NULL_TREE, section_str);

	id = get_identifier("__section__");
	attr = DECL_ATTRIBUTES(fndecl);
	DECL_ATTRIBUTES(fndecl) = tree_cons(id, attr_args, attr);

#if BUILDING_GCC_VERSION < 5000
	DECL_SECTION_NAME(fndecl) = section_str;
#endif
	set_decl_section_name(fndecl, section_name);
}

/* Find all functions that can become __init/__exit functions */
static unsigned int search_init_functions_execute(void)
{
	struct cgraph_node *node;

	if (flag_lto && !in_lto_p)
		return 0;

	FOR_EACH_FUNCTION(node)
		NODE_SYMBOL(node)->aux = (void *)NONE;

	while (search_init_exit_callers()) {};

	FOR_EACH_FUNCTION(node) {
		move_function_to_init_exit_text(node);

		NODE_SYMBOL(node)->aux = NULL;
	}

	return 0;
}

/* Find the specified argument in the clone */
static unsigned int orig_argnum_on_clone(struct cgraph_node *new_node,
						unsigned int orig_argnum)
{
	bitmap args_to_skip;
	unsigned int i, new_argnum = orig_argnum;

	gcc_assert(new_node->clone_of && new_node->clone.tree_map);
	args_to_skip = new_node->clone.args_to_skip;
	if (bitmap_bit_p(args_to_skip, orig_argnum - 1))
		return 0;

	for (i = 0; i < orig_argnum; i++) {
		if (bitmap_bit_p(args_to_skip, i))
			new_argnum--;
	}

	return new_argnum + 1;
}

/* Determine if a cloned function has all the original arguments */
static bool unchanged_arglist(struct cgraph_node *new_node,
				struct cgraph_node *old_node)
{
	const_tree new_decl_list, old_decl_list;

	if (new_node->clone_of && new_node->clone.tree_map)
		return !new_node->clone.args_to_skip;

	new_decl_list = DECL_ARGUMENTS(NODE_DECL(new_node));
	old_decl_list = DECL_ARGUMENTS(NODE_DECL(old_node));
	if (new_decl_list != NULL_TREE && old_decl_list != NULL_TREE)
		gcc_assert(list_length(new_decl_list) ==
						list_length(old_decl_list));

	return true;
}

static void initify_node_duplication_hook(struct cgraph_node *src,
						struct cgraph_node *dst,
						void *data __unused)
{
	const_tree orig_fndecl, orig_decl_lst, arg;
	unsigned int orig_argnum = 0;

	if (unchanged_arglist(dst, src))
		return;

	orig_fndecl = NODE_DECL(src);
	if (!has_nocapture_param(orig_fndecl))
		return;

	orig_decl_lst = DECL_ARGUMENTS(orig_fndecl);
	gcc_assert(orig_decl_lst != NULL_TREE);

	for (arg = orig_decl_lst; arg; arg = TREE_CHAIN(arg), orig_argnum++) {
		if (!is_nocapture_param(orig_fndecl, orig_argnum))
			continue;
		if (orig_argnum_on_clone(dst, orig_argnum) == 0)
			continue;

		debug_cgraph_node(dst);
		debug_cgraph_node(src);
		gcc_unreachable();
	}
}

static void initify_register_hooks(void)
{
	static bool init_p = false;

	if (init_p)
		return;
	init_p = true;

	node_duplication_hook_holder =
		cgraph_add_node_duplication_hook(&initify_node_duplication_hook,
									NULL);
}

static void search_init_functions_generate_summary(void)
{
	initify_register_hooks();
}

static void search_init_functions_read_summary(void)
{
	initify_register_hooks();
}

#define PASS_NAME search_init_functions
#define NO_WRITE_SUMMARY
#define NO_READ_OPTIMIZATION_SUMMARY
#define NO_WRITE_OPTIMIZATION_SUMMARY
#define NO_STMT_FIXUP
#define NO_FUNCTION_TRANSFORM
#define NO_VARIABLE_TRANSFORM

#include "gcc-generate-ipa-pass.h"

static unsigned int (*old_section_type_flags)(tree decl, const char *name,
								int reloc);

static unsigned int initify_section_type_flags(tree decl, const char *name,
								int reloc)
{
	if (!strcmp(name, ".init.rodata.str") ||
					!strcmp(name, ".exit.rodata.str")) {
		gcc_assert(TREE_CODE(decl) == VAR_DECL);
		gcc_assert(DECL_INITIAL(decl));
		gcc_assert(TREE_CODE(DECL_INITIAL(decl)) == STRING_CST);

		return 1 | SECTION_MERGE | SECTION_STRINGS;
	}

	return old_section_type_flags(decl, name, reloc);
}

static void initify_start_unit(void __unused *gcc_data,
						void __unused *user_data)
{
	old_section_type_flags = targetm.section_type_flags;
	targetm.section_type_flags = initify_section_type_flags;
}

int plugin_init(struct plugin_name_args *plugin_info,
					struct plugin_gcc_version *version)
{
	struct register_pass_info initify_pass_info, search_init_functions_info;
	int i;
	const int argc = plugin_info->argc;
	bool enabled = true;
	const struct plugin_argument * const argv = plugin_info->argv;
	const char * const plugin_name = plugin_info->base_name;

	initify_pass_info.pass				= make_initify_pass();
	initify_pass_info.reference_pass_name		= "nrv";
	initify_pass_info.ref_pass_instance_number	= 1;
	initify_pass_info.pos_op			= PASS_POS_INSERT_AFTER;

	search_init_functions_info.pass = make_search_init_functions_pass();
	search_init_functions_info.reference_pass_name		= "inline";
	search_init_functions_info.ref_pass_instance_number	= 1;
	search_init_functions_info.pos_op = PASS_POS_INSERT_AFTER;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	for (i = 0; i < argc; ++i) {
		if (!(strcmp(argv[i].key, "disable"))) {
			enabled = false;
			continue;
		}
		if (!strcmp(argv[i].key, "verbose")) {
			verbose = true;
			continue;
		}
		if (!strcmp(argv[i].key, "print_missing_attr")) {
			print_missing_attr = true;
			continue;
		}
		if (!strcmp(argv[i].key, "search_init_exit_functions")) {
			search_init_exit_functions = true;
			continue;
		}

		error(G_("unkown option '-fplugin-arg-%s-%s'"), plugin_name,
								argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &initify_plugin_info);
	if (enabled) {
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
							&initify_pass_info);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
						&search_init_functions_info);
		register_callback(plugin_name, PLUGIN_START_UNIT,
						initify_start_unit, NULL);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes,
									NULL);

	return 0;
}
