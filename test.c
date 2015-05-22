/* result:
    test.c:28:17: note: initified local var: print_init: print_init
    test.c:29:2: note: initified function arg: print_init: [%s]
    test.c:29:2: note: initified function arg: print_init: [nyuszimuszi
    ]
 */

#include <stdio.h>

#define __section(S) __attribute__ ((__section__(#S)))
#define __init __section(.init.text)

#define __constsection(x) __section(x)
#define __initconst __constsection(.init.rodata)

#define __printf(a, b) __attribute__((nocapture(a, b)))

int __attribute__((noinline)) __printf(1, 3) print(const char *format, const char *d, const char *str)
{
	return printf(format, str);
}

void __init print_init(const char *str)
{
	unsigned int i;
	static const char static_str[] = "cicamica";

	printf("%s %s\n", static_str, str);
	printf("%s\n", __func__);
	print("%s", "asd", "nyuszimuszi\n");
	printf("cica\n");
}

int main(void)
{
	static const char str[] = "sdcvxcv";

	print_init(str);
	return 0;
}
