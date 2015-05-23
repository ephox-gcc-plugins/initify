/* result:
test.c:43:21: note: initified local var: print_init: print_init
test.c:44:14: note: initified function arg: print_init: [YES %s]
test.c:44:14: note: initified function arg: print_init: [YES_nyuszimuszi
]
test.c:46:14: note: initified function arg: print_init: [YES %s %s %s]
test.c:46:14: note: initified function arg: print_init: [YES_FFF]
test.c:46:14: note: initified function arg: print_init: [YES_GGG]
test.c:46:14: note: initified function arg: print_init: [YES_HHH]
 */

#include <stdio.h>
#include <stdarg.h>

#define __section(S) __attribute__ ((__section__(#S)))
#define __init __section(.init.text)

#define __constsection(x) __section(x)
#define __initconst __constsection(.init.rodata)

#define __printf(a, b) __attribute__((nocapture(a, b)))

int __attribute__((noinline)) __attribute__((nocapture(2))) print_vararg(const char *d, const char *str, ...)
{
	va_list args;

	va_start(args, str);
	while (*str != '\0')
		printf("%s\n", (const char *)va_arg(args, int));
	va_end(args);

	return printf(d);
}

int __attribute__((noinline)) __printf(1, 3) print_simple(const char *format, const char *d, const char *str)
{
	return printf(format, str);
}

void __init print_init(const char *str)
{
	unsigned int i;
	static const char static_str[] = "NO_cicamica";

	printf("NO %s %s\n", static_str, str);

	printf("YES %s\n", __func__);
	print_simple("YES %s", "NO_asd", "YES_nyuszimuszi\n");
	printf("NO cica\n");
	print_vararg("NO_aaa", "YES %s %s %s", "YES_FFF", "YES_GGG", "YES_HHH");
}

int main(void)
{
	static const char str[] = "NO_sdcvxcv";

	print_init(str);
	return 0;
}
