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

static bool has__init_attribute(const_tree decl)
{
	const_tree section;
	tree attr_value;

	section = lookup_attribute("section", DECL_ATTRIBUTES(decl));
	if (!section)
		return false;
	if (!TREE_VALUE(section))
		return false;

	for (attr_value = TREE_VALUE(section); attr_value; attr_value = TREE_CHAIN(attr_value)) {
		const char *str = TREE_STRING_POINTER(TREE_VALUE(attr_value));

		if (!strncmp(str, ".init.", 6))
			return true;
		if (!strncmp(str, ".exit.", 6))
			return true;
	}

	return false;
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

static bool set__initconst_attr(tree decl)
{
	gcc_assert(DECL_P(decl));

	if (has__init_attribute(decl))
		return false;

#if BUILDING_GCC_VERSION < 5000
	DECL_SECTION_NAME(decl) = build_string(13, ".init.rodata");
#else
	set_decl_section_name(decl, ".init.rodata");
#endif
	return true;
}

static void search_local_strs(void)
{
	unsigned int i;
	tree var;

	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		tree str, init_val = DECL_INITIAL(var);

		if (init_val == NULL_TREE)
			continue;
		str = get_string_cst(init_val);
		if (str == NULL_TREE)
			continue;
		if (set__initconst_attr(var))
			fprintf(stderr, "initify: %s: %s\n", DECL_NAME_POINTER(current_function_decl), TREE_STRING_POINTER(str));
	}
}

static tree create_tmp_assign(gcall *stmt, unsigned int num)
{
	tree str, type, new_arg, decl, arg = gimple_call_arg(stmt, num);

	str = get_string_cst(arg);
	decl = build_decl(DECL_SOURCE_LOCATION(current_function_decl), VAR_DECL, create_tmp_var_name("cicus"), TREE_TYPE(str));

	TYPE_SIZES_GIMPLIFIED(TREE_TYPE(decl)) = 1;
	TYPE_SIZES_GIMPLIFIED(TYPE_DOMAIN(TREE_TYPE(decl))) = 1;
	type = TREE_TYPE(TREE_TYPE(decl));
	TYPE_READONLY(type) = 1;
	TREE_PUBLIC(type) = 0;

	DECL_INITIAL(decl) = str;
	DECL_CONTEXT(decl) = current_function_decl;
	DECL_ARTIFICIAL(decl) = 1;
#if BUILDING_GCC_VERSION <= 4009
	DECL_ABSTRACT(decl) = 0;
#endif

	TREE_STATIC(decl) = 1;
	TREE_READONLY(decl) = 1;
	TREE_ADDRESSABLE(decl) = 1;
	TREE_USED(decl) = 1;

#if BUILDING_GCC_VERSION <= 4007
	lang_hooks.dup_lang_specific_decl(decl);
	create_var_ann(decl);
	varpool_mark_needed_node(varpool_node(decl));
	add_referenced_var(decl);
#endif

#if BUILDING_GCC_VERSION >= 4006
	add_local_decl(cfun, decl);
#endif
	varpool_finalize_decl(decl);

	new_arg = build_unary_op(DECL_SOURCE_LOCATION(current_function_decl), ADDR_EXPR, decl, 0);
	gimple_call_set_arg(stmt, num, new_arg);
	update_stmt(stmt);

	return decl;
}

static void search_str_param(gcall *stmt)
{
	unsigned int num;
	const_tree fndecl;

	fndecl = gimple_call_fndecl(stmt);
	if (fndecl == NULL_TREE)
		return;

	for (num = 0; num < gimple_call_num_args(stmt); num++) {
		tree var, str, arg = gimple_call_arg(stmt, num);

		str = get_string_cst(arg);
		if (str == NULL_TREE)
			continue;

		var = create_tmp_assign(stmt, num);
		if (set__initconst_attr(var))
			fprintf(stderr, "initify: %s: %s\n", DECL_NAME_POINTER(current_function_decl), TREE_STRING_POINTER(str));
	}
}

static void search_const_strs(void)
{
	basic_block bb;

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt = gsi_stmt(gsi);

			if (is_gimple_call(stmt))
				search_str_param(as_a_gcall(stmt));
		}
	}
}

static unsigned int handle_function(void)
{
	if (!has__init_attribute(current_function_decl))
		return 0;

	search_local_strs();
	search_const_strs();

	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
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
namespace {
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
#endif

static struct opt_pass *make_initify_plugin_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new initify_plugin_pass();
#else
	return &initify_plugin_pass.pass;
#endif
}

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

	return 0;
}
