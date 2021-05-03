#include "Imports.h"


__forceinline char locase_a(char c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

__forceinline wchar_t locase_w(wchar_t c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

int _strcmpi_a(const char *s1, const char *s2)
{
	char c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = locase_a(*s1);
		c2 = locase_a(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (int)(c1 - c2);
}

int _strcmpi_w(const wchar_t *s1, const wchar_t *s2)
{
	wchar_t c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = locase_w(*s1);
		c2 = locase_w(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (int)(c1 - c2);
}

char *_strcat_a(char *dest, const char *src)
{
	if ((dest == 0) || (src == 0))
		return dest;

	while (*dest != 0)
		dest++;

	while (*src != 0) {
		*dest = *src;
		dest++;
		src++;
	}

	*dest = 0;
	return dest;
}

wchar_t *_strcat_w(wchar_t *dest, const wchar_t *src)
{
	if ((dest == 0) || (src == 0))
		return dest;

	while (*dest != 0)
		dest++;

	while (*src != 0) {
		*dest = *src;
		dest++;
		src++;
	}

	*dest = 0;
	return dest;
}


size_t _strlen_a(const char *s)
{
	char *s0 = (char *)s;

	if (s == 0)
		return 0;

	while (*s != 0)
		s++;

	return (s - s0);
}

size_t _strlen_w(const wchar_t *s)
{
	wchar_t *s0 = (wchar_t *)s;

	if (s == 0)
		return 0;

	while (*s != 0)
		s++;

	return (s - s0);
}
