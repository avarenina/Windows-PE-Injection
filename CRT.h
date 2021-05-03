#pragma once

void  __stdcall m_memset(void* dst, unsigned char ucByte, DWORD dwSize);
void* __stdcall m_memcpy(void *szBuf, const void *szStr, int nLen);
int m_memcmp(const void *s1, const void *s2, size_t n);
