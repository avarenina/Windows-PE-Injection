#include "Imports.h"


#pragma optimize("", off)
__declspec (naked) void  __stdcall m_memset(void* dst, unsigned char ucByte, DWORD dwSize) 
{
	__asm
	{
		mov edx, dword ptr[esp + 4]
		mov eax, dword ptr[esp + 8]
		mov ebx, dword ptr[esp + 12]
		Begin:
		mov byte ptr[edx], AL
			inc edx
			dec ebx
			jnz Begin
			ret 8
	}
}


#pragma optimize("", off)
__declspec(naked)  void* __stdcall m_memcpy(void *szBuf, const void *szStr, int nLen)
{
	__asm
	{
		push esi
		push edi
		push ecx
		mov esi, dword ptr[esp + 20]
		mov edi, dword ptr[esp + 16]
		mov ecx, dword ptr[esp + 24]
		rep movsb
		pop ecx
		pop edi
		pop esi
		ret 12
	}
}

#pragma optimize("", off)
int m_memcmp(const void *s1, const void *s2, size_t n)
{
	if (n != 0) {
		const unsigned char *p1 = s1, *p2 = s2;

		do {
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	return (0);
}