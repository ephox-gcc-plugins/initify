/*
 * Copyright 2011-2015 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * https://github.com/ephox-gcc-plugins/initify
 *
 * Move string constants referenced in __init functions only to __initconst
 *
 * Usage:
 * $ make
 * $ make run
 */

#include "gcc-common.h"

int plugin_is_GPL_compatible;

static struct plugin_info initify_plugin_info = {
	.version	= "20150521",
	.help		= "initify_plugin\n",
};

static tree handle_nocapture_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	enum tree_code code = TREE_CODE(*node);

	switch (code) {
	case FUNCTION_DECL:
	case FUNCTION_TYPE:
	case METHOD_TYPE:
		break;
	case TYPE_DECL: {
		const_tree fntype = TREE_TYPE(*node);

		if (TREE_CODE(fntype) == POINTER_TYPE)
			fntype = TREE_TYPE(fntype);
		if (TREE_CODE(fntype) == FUNCTION_TYPE || TREE_CODE(fntype) == METHOD_TYPE)
			break;
		// FALLTHROUGH
	}
	default:
		*no_add_attrs = true;
		debug_tree(*node);
		error("%s: %qE attribute only applies to functions", __func__, name);
		return NULL_TREE;
	}

	for (; args; args = TREE_CHAIN(args)) {
		tree position = TREE_VALUE(args);

		if (TREE_CODE(position) != INTEGER_CST) {
			error("%s: parameter isn't an integer", __func__);
			debug_tree(args);
			*no_add_attrs = true;
			return NULL_TREE;
		}
	}
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

static const char *get_init_exit_section(const_tree decl)
{
	const_tree section;
	tree attr_value;

	section = lookup_attribute("section", DECL_ATTRIBUTES(decl));
	if (!section)
		return NULL;

	gcc_assert(TREE_VALUE(section));
	for (attr_value = TREE_VALUE(section); attr_value; attr_value = TREE_CHAIN(attr_value)) {
		const char *str = TREE_STRING_POINTER(TREE_VALUE(attr_value));

		if (!strncmp(str, ".init.", 6))
			return str;
		if (!strncmp(str, ".exit.", 6))
			return str;
	}

	return NULL;
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

static bool set_init_exit_section(tree decl, bool initexit)
{
	const char *str;

	gcc_assert(DECL_P(decl));

	str = get_init_exit_section(decl);
	if (str)
		return false;

	if (initexit)
		set_decl_section_name(decl, ".init.rodata");
	else
		set_decl_section_name(decl, ".exit.rodata");
	return true;
}

static void search_local_strs(bool initexit)
{
	unsigned int i;
	tree var;

	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		tree str, init_val = DECL_INITIAL(var);

		if (init_val == NULL_TREE)
			continue;
		if (strcmp(DECL_NAME_POINTER(var), "__func__"))
			continue;

		str = get_string_cst(init_val);
		gcc_assert(str);

		if (set_init_exit_section(var, initexit))
			inform(DECL_SOURCE_LOCATION(var), "initified local var: %s: %s", DECL_NAME_POINTER(current_function_decl), TREE_STRING_POINTER(str));
	}
}

static tree create_tmp_assign(gcall *stmt, unsigned int num)
{
	tree str, type, decl, arg = gimple_call_arg(stmt, num);

	str = get_string_cst(arg);
	decl = build_decl(DECL_SOURCE_LOCATION(current_function_decl), VAR_DECL, create_tmp_var_name("cicus"), TREE_TYPE(str));

	type = TREE_TYPE(TREE_TYPE(decl));
	TYPE_READONLY(type) = 1;
	TREE_PUBLIC(type) = 0;

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
	BLOCK_VARS(DECL_INITIAL (current_function_decl)) = decl;

	decl = build_unary_op(DECL_SOURCE_LOCATION(current_function_decl), ADDR_EXPR, decl, 0);
	gimple_call_set_arg(stmt, num, decl);
	update_stmt(stmt);

	return TREE_OPERAND(decl, 0);
}

static bool is_in_nocapture_attr_value(const_gimple stmt, unsigned int num)
{
	unsigned int attr_arg_val = 0;
	tree attr, attr_val;
	const_tree fndecl = gimple_call_fndecl(stmt);

	gcc_assert(DECL_ABSTRACT_ORIGIN(fndecl) == NULL_TREE);
	attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(fndecl));

	for (attr_val = TREE_VALUE(attr); attr_val; attr_val = TREE_CHAIN(attr_val)) {
		attr_arg_val = (unsigned int)tree_to_uhwi(TREE_VALUE(attr_val));

		if (attr_arg_val == num + 1)
			return true;
	}

	gcc_assert(attr_arg_val != 0);

	// vararg
	return attr_arg_val < num + 1;
}

static void search_str_param(gcall *stmt, bool initexit)
{
	unsigned int num;

	for (num = 0; num < gimple_call_num_args(stmt); num++) {
		tree var, str, arg = gimple_call_arg(stmt, num);

		str = get_string_cst(arg);
		if (str == NULL_TREE)
			continue;

		if (!is_in_nocapture_attr_value(stmt, num))
			continue;

		var = create_tmp_assign(stmt, num);
		if (set_init_exit_section(var, initexit))
			inform(gimple_location(stmt), "initified function arg: %s: [%s]", DECL_NAME_POINTER(current_function_decl), TREE_STRING_POINTER(str));
	}
}

static bool has_nocapture_attr(const gcall *stmt)
{
	const_tree attr, fndecl = gimple_call_fndecl(stmt);

	if (fndecl == NULL_TREE)
		return false;

	attr = lookup_attribute("nocapture", DECL_ATTRIBUTES(fndecl));
	return attr != NULL_TREE;
}

static void search_const_strs(bool initexit)
{
	basic_block bb;

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt = gsi_stmt(gsi);

			if (!is_gimple_call(stmt))
				continue;
			if (has_nocapture_attr(as_a_gcall(stmt)))
				search_str_param(as_a_gcall(stmt), initexit);
		}
	}
}

static unsigned int handle_function(void)
{
	bool initexit;
	const char *section = get_init_exit_section(current_function_decl);

	if (!section)
		return 0;

	initexit = !strncmp(section, ".init.", 6);
	search_local_strs(initexit);
	search_const_strs(initexit);

	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
namespace {
static const struct pass_data initify_plugin_pass_data = {
#else
static struct gimple_opt_pass initify_plugin_pass = {
	.pass = {
#endif
		.type			= GIMPLE_PASS,
		.name			= "initify_plugin",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 5000
#elif BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= handle_function,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_dump_func | TODO_verify_ssa | TODO_verify_stmts | TODO_remove_unused_locals | TODO_update_ssa_no_phi | TODO_cleanup_cfg | TODO_ggc_collect | TODO_verify_flow
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
class initify_plugin_pass : public gimple_opt_pass {
public:
	initify_plugin_pass() : gimple_opt_pass(initify_plugin_pass_data, g) {}
#if BUILDING_GCC_VERSION >= 5000
	virtual unsigned int execute(function *) { return handle_function(); }
#else
	unsigned int execute() { return handle_function(); }
#endif
};
}

static struct opt_pass *make_initify_plugin_pass(void)
{
	return new initify_plugin_pass();
}
#else
static struct opt_pass *make_initify_plugin_pass(void)
{
	return &initify_plugin_pass.pass;
}
#endif

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	struct register_pass_info initify_plugin_pass_info;

	initify_plugin_pass_info.pass				= make_initify_plugin_pass();
	initify_plugin_pass_info.reference_pass_name		= "nrv";
	initify_plugin_pass_info.ref_pass_instance_number	= 1;
	initify_plugin_pass_info.pos_op				= PASS_POS_INSERT_AFTER;

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &initify_plugin_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &initify_plugin_pass_info);
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}
