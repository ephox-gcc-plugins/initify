/* result:
 *  initify: print_init: cicamica
 *  initify: print_init: %s %s
 *  initify: print_init: nyuszimuszi
 */

#include <stdio.h>

#define __section(S) __attribute__ ((__section__(#S)))
#define __init __section(.init.text)

#define __constsection(x) __section(x)
#define __initconst __constsection(.init.rodata)

void __init print_init(const char *str)
{
	unsigned int i;
	static const char static_str[] = "cicamica";

	printf("%s %s\n", static_str, str);
	printf("nyuszimuszi\n");
}

int main(void)
{
	static const char str[] = "sdcvxcv";

	print_init(str);
	return 0;
}
