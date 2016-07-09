/* result:

initified local var: _1_YES_print_exit: _1_YES_print_exit
initified local var: _1_YES_print_init: _1_YES_print_init
initified function arg: _1_YES_print_init: ["4. YES %s %s %s"]
initified function arg: _1_YES_print_init: ["5. YES"]
initified function arg: _1_YES_print_init: ["6. YES"]
initified function arg: _1_YES_print_init: ["7. YES"]
initified function arg: _1_YES_print_init: ["8. YES"]
initified function arg: _1_YES_print_init: ["9. YES %s"]
initified function arg: _1_YES_print_init: ["10. YES"]
initified function arg: _1_YES_print_init: ["11. YES %s %d"]
initified function arg: _1_YES_print_init: ["12. YES"]
initified function arg: _1_YES_print_init: ["13. YES"]
initified function arg: _1_YES_print_init: ["14. YES"]
initified function arg: _1_YES_print_init: ["15. YES %s %s %s"]
initified function arg: _1_YES_print_init: ["16. YES"]
initified function arg: _1_YES_print_init: ["17. YES"]
initified function arg: _1_YES_print_init: ["18. YES"]
initified function arg: _1_YES_print_init: ["19. YES"]
initified local var: _20_YES_func: _20_YES_func
initified local var: _21_YES_func: _21_YES_func
initified function arg: _1_YES_print_init: ["22. YES"]
initified function arg: _1_YES_print_init: ["23. YES"]
initified local var, phi arg: _1_YES_print_init: ["24. YES"]
initified local var, phi arg: _1_YES_print_init: ["25. YES"]
initified local var, phi arg: _1_YES_print_exit: ["26. YES"]

objdump -s -j .init.rodata.str test
objdump -s -j .exit.rodata.str test

initified function arg: print_simple_should_init.isra.0.constprop: ["SHOULD_INIT"]

__init attribute is missing from the 'print_simple_should_init.isra' function
*/

#include <stdio.h>
#include <stdarg.h>

#define __section(S) __attribute__ ((__section__(#S)))
#define __init __section(.init.text)
#define __exit __section(.exit.text)

#define __constsection(x) __section(x)
#define __initconst __constsection(.init.rodata)
#define __exitconst __constsection(.exit.rodata)

#define __printf(a, b) __attribute__((nocapture(a, b)))

int __printf(3, 0) __attribute__((nocapture(2))) print_vararg_no_vararg(const char *d, const char *a, const char *str, ...)
{
	va_list args;

	va_start(args, str);
	printf("%s\n", va_arg(args, const char *));
	va_end(args);

	return printf(d);
}

int __attribute__((nocapture(1, 3))) print_format_and_vararg(const char *d, const char *str, ...)
{
	va_list args;

	va_start(args, str);
	printf("%s\n", va_arg(args, const char *));
	printf("%s\n", va_arg(args, const char *));
	printf("%s\n", va_arg(args, const char *));
	va_end(args);

	return printf(d);
}

int __attribute__((nocapture(3))) print_vararg(const char *d, const char *str, ...)
{
	va_list args;

	va_start(args, str);
	printf("%s\n", va_arg(args, const char *));
	printf("%s\n", va_arg(args, const char *));
	printf("%s\n", va_arg(args, const char *));
	va_end(args);

	return printf(d);
}

int __printf(1, 3) __attribute__((nocapture(2))) print_vararg_2(const char *d, const char *str, ...)
{
	va_list args;

	va_start(args, str);
	printf("%s\n", va_arg(args, const char *));
	printf("%s\n", va_arg(args, const char *));
	printf("%s\n", va_arg(args, const char *));
	va_end(args);

	return printf(d);
}

int __attribute__((nocapture(1))) print_vararg_3(const char *d, const char *str, ...)
{
	va_list args;

	va_start(args, str);
	printf("%s\n", va_arg(args, const char *));
	va_end(args);

	return printf(d);
}

static int __attribute__((nocapture(1))) print_simple_2(const char *format)
{
	return printf(format, format, format);
}

int __attribute__((nocapture)) print_simple_3(const char *format, const char *d)
{
	return printf(format, d);
}

static int __attribute__((nocapture(1))) print_simple_4(const char *format)
{
	return printf(format, format, format);
}

static int __printf(1, 3) print_simple_should_init(const char *format, const char *d, const char *str, const char *str2)
{
	print_simple_4("SHOULD_INIT");
	return printf(format, str, str2);
}

void __exit _1_YES_print_exit(const char *str)
{
	print_simple_4(str?__func__:"26. YES");
}

void __init _1_YES_print_init(const char *str)
{
	unsigned int i;
	const char *local_str, *local_str_2;
	int (*print_fn)(const char *format);
	static const char static_str[] = "NO_cicamica";

	printf("1. NO %s %s\n", static_str, str);

	if (!str) {
		local_str = "24. YES";
		local_str_2 = "12. NO";
	} else {
		local_str = "25. YES";
		local_str_2 = "13. NO";
	}

	if (str)
		print_fn = &print_simple_2;
	else
		print_fn = &print_simple_4;
	print_fn("47. NO");
	print_simple_2(local_str);
	printf(local_str_2);
	print_simple_2(__func__);
	print_simple_should_init("2. YES %s", "2. NO", "3. YES\n", "3. NO");
//	print_simple_should_init("27. YES %s", "21. NO", "38. YES\n", "31. NO");
	printf("4. NO\n");
	print_vararg("5. NO", "6. NO", "4. YES %s %s %s", "5. YES", "6. YES", "7. YES");
	print_vararg_no_vararg("7. NO", "8. YES", "9. YES %s", "8. NO");
	print_format_and_vararg("10. YES", "9. NO", "11. YES %s %d", "12. YES");
	print_vararg_2("13. YES", "14. YES", "15. YES %s %s %s", "16. YES", "17. YES", "18. YES");
	print_vararg_3("19. YES", "10. NO", "11. NO %s %s %s");
	print_simple_3("22. YES", "23. YES");
}

void _21_not_init(const char *str)
{
	unsigned int i;
	const char *local_str_2;
	static const char static_str[] = "14. NO_cicamica";

	printf("15. NO %s %s\n", static_str, str);

	if (!str)
		local_str_2 = "17. NO";
	else
		local_str_2 = "19. NO";

	printf(local_str_2);
	printf("20. NO\n");
	print_vararg("22. NO", "23. NO", "24. NO %s %s %s", "25. NO", "26. NO", "27. NO");
	print_vararg_no_vararg("28. NO", "29. NO", "30. NO %s", "31. NO");
	print_format_and_vararg("32. NO", "33. NO", "34. NO %s %d", "35. NO");
	print_vararg_2("36. NO", "37. NO", "38. NO %s %s %s", "39. NO", "40. NO", "41. NO");
	print_vararg_3("42. NO", "43. NO", "44. NO %s %s %s");
	print_simple_3("45. NO", "46. NO");
}

void __init _20_YES_func(void)
{
	print_simple_2(__func__);
}

void __init _21_YES_func(void)
{
	print_simple_2(__func__);
}

void no_print(const char *str)
{
	printf("%s\n", str);
}

void __init _12_NO_func(void)
{
	printf("%s\n", __func__);
	no_print(__func__);
}

struct dd { const char *func; };
void dd_print(const struct dd *dd)
{
	printf("%s\n", dd->func);
}

void __init _13_NO_func(void)
{
	static struct x {
		struct {
			const char *n;
		} f;
	} xx = {
		.f = {
			.n = __func__,
		},
	};

	dd_print(&xx);
}

void __init _14_NO_func(void)
{
	static const struct dd ee = { .func = __func__  + 1};

	dd_print(&ee);
}

void __init _15_NO_func(void)
{
	asm("" : : "r"(&__func__));
}

int main(void)
{
	static const char str[] = "10. NO";

	_1_YES_print_init(str);
	_12_NO_func();
	return 0;
}
