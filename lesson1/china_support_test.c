#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

int main(void)
{
	wchar_t* b = L"是恶人";
	wchar_t* bs = L"是恶人sss";
	setlocale(LC_CTYPE,"zh_CN.utf8");
	printf("%ls\n",bs);
	return 0;
}
