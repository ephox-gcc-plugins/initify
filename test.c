/* result:

initified local var: _1_YES_print_init: _1_YES_print_init
initified function arg: _1_YES_print_init: [2. YES %s]
initified function arg: _1_YES_print_init: [3. YES
initified function arg: _1_YES_print_init: [4. YES %s %s %s]
initified function arg: _1_YES_print_init: [5. YES]
initified function arg: _1_YES_print_init: [6. YES]
initified function arg: _1_YES_print_init: [7. YES]
initified function arg: _1_YES_print_init: [8. YES]
initified function arg: _1_YES_print_init: [9. YES %s]
initified function arg: _1_YES_print_init: [10. YES]
initified function arg: _1_YES_print_init: [11. YES %s %d]
initified function arg: _1_YES_print_init: [12. YES]
initified function arg: _1_YES_print_init: [13. YES]
initified function arg: _1_YES_print_init: [14. YES]
initified function arg: _1_YES_print_init: [15. YES %s %s %s]
initified function arg: _1_YES_print_init: [16. YES]
initified function arg: _1_YES_print_init: [17. YES]
initified function arg: _1_YES_print_init: [18. YES]
initified function arg: _1_YES_print_init: [19. YES]
initified local var: _20_YES_func: _20_YES_func
initified local var: _21_YES_func: _21_YES_func
initified function arg: _1_YES_print_init: ["22. YES"]
initified function arg: _1_YES_print_init: ["23. YES"]

objdump -s -j .init.rodata.str test
*/

#include <stdio.h>
#include <stdarg.h>

#define __section(S) __attribute__ ((__section__(#S)))
#define __init __section(.init.text)

#define __constsection(x) __section(x)
#define __initconst __constsection(.init.rodata)

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

int __printf(1, 3) print_simple(const char *format, const char *d, const char *str, const char *str2)
{
	return printf(format, str, str2);
}

int __attribute__((nocapture(1))) print_simple_2(const char *format)
{
	return printf(format, format, format);
}

int __attribute__((nocapture(-1))) print_simple_3(const char *format, const char *d)
{
	return printf(format, d);
}

void __init _1_YES_print_init(const char *str)
{
	unsigned int i;
	static const char static_str[] = "NO_cicamica";

	printf("1. NO %s %s\n", static_str, str);

	print_simple_2(__func__);
	print_simple("2. YES %s", "2. NO", "3. YES\n", "3. NO");
	printf("4. NO\n");
	print_vararg("5. NO", "6. NO", "4. YES %s %s %s", "5. YES", "6. YES", "7. YES");
	print_vararg_no_vararg("7. NO", "8. YES", "9. YES %s", "8. NO");
	print_format_and_vararg("10. YES", "9. NO", "11. YES %s %d", "12. YES");
	print_vararg_2("13. YES", "14. YES", "15. YES %s %s %s", "16. YES", "17. YES", "18. YES");
	print_vararg_3("19. YES", "10. NO", "11. NO %s %s %s");
	print_simple_3("22. YES", "23. YES");
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
	static const struct dd dd = { .func = __func__ };
	dd_print(&dd);
}

int main(void)
{
	static const char str[] = "10. NO";

	_1_YES_print_init(str);
	_12_NO_func();
	return 0;
}
