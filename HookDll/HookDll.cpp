// HookDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "HookDll.h"


// ���ǵ���������һ��ʾ��
HOOKDLL_API int nHookDll=0;

// ���ǵ���������һ��ʾ����
HOOKDLL_API int fnHookDll(void)
{
	return 42;
}

// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� HookDll.h
CHookDll::CHookDll()
{
	return;
}
