#include "gbadisasm.h"
#include "disasm.h"

const CGbadisasm::SOption CGbadisasm::s_Option[] =
{
	{ USTR("input"), USTR('i'), USTR("the GBA rom to disassemble") },
	{ USTR("output"), USTR('o'), USTR("the output file to write to") },
	{ USTR("config"), USTR('c'), USTR("a config file that gives hints to the disassembler")},
	{ USTR("address"), USTR('l'), USTR("where the rom is linked to -- defaults to 0x8000000")},
	{ USTR("standalone"), USTR('s'), USTR("assume there's no rom header when present")},
	{ USTR("verbose"), USTR('v'), USTR("show the info") },
	{ USTR("sample"), 0, USTR("show the samples") },
	{ USTR("help"), USTR('h'), USTR("show this help") },
	{ nullptr, 0, nullptr }
};

CGbadisasm::CGbadisasm()
	: m_eAction(kActionNone)
	, m_uAddress(0x08000000)
	, m_bStandalone(false)
	, m_bVerbose(false)
{
}

CGbadisasm::~CGbadisasm()
{
}

int CGbadisasm::ParseOptions(int a_nArgc, UChar* a_pArgv[])
{
	if (a_nArgc <= 1)
	{
		return 1;
	}
	for (int i = 1; i < a_nArgc; i++)
	{
		int nArgpc = static_cast<int>(UCslen(a_pArgv[i]));
		if (nArgpc == 0)
		{
			continue;
		}
		int nIndex = i;
		if (a_pArgv[i][0] != USTR('-'))
		{
			UPrintf(USTR("ERROR: illegal option\n\n"));
			return 1;
		}
		else if (nArgpc > 1 && a_pArgv[i][1] != USTR('-'))
		{
			for (int j = 1; j < nArgpc; j++)
			{
				switch (parseOptions(a_pArgv[i][j], nIndex, a_nArgc, a_pArgv))
				{
				case kParseOptionReturnSuccess:
					break;
				case kParseOptionReturnIllegalOption:
					UPrintf(USTR("ERROR: illegal option\n\n"));
					return 1;
				case kParseOptionReturnNoArgument:
					UPrintf(USTR("ERROR: no argument\n\n"));
					return 1;
				case kParseOptionReturnUnknownArgument:
					UPrintf(USTR("ERROR: unknown argument \"%") PRIUS USTR("\"\n\n"), m_sMessage.c_str());
					return 1;
				case kParseOptionReturnOptionConflict:
					UPrintf(USTR("ERROR: option conflict\n\n"));
					return 1;
				}
			}
		}
		else if (nArgpc > 2 && a_pArgv[i][1] == USTR('-'))
		{
			switch (parseOptions(a_pArgv[i] + 2, nIndex, a_nArgc, a_pArgv))
			{
			case kParseOptionReturnSuccess:
				break;
			case kParseOptionReturnIllegalOption:
				UPrintf(USTR("ERROR: illegal option\n\n"));
				return 1;
			case kParseOptionReturnNoArgument:
				UPrintf(USTR("ERROR: no argument\n\n"));
				return 1;
			case kParseOptionReturnUnknownArgument:
				UPrintf(USTR("ERROR: unknown argument \"%") PRIUS USTR("\"\n\n"), m_sMessage.c_str());
				return 1;
			case kParseOptionReturnOptionConflict:
				UPrintf(USTR("ERROR: option conflict\n\n"));
				return 1;
			}
		}
		i = nIndex;
	}
	return 0;
}

int CGbadisasm::CheckOptions() const
{
	if (m_eAction == kActionNone)
	{
		UPrintf(USTR("ERROR: nothing to do\n\n"));
		return 1;
	}
	if (m_eAction != kActionSample && m_eAction != kActionHelp && m_sInputFileName.empty())
	{
		UPrintf(USTR("ERROR: no --input option\n\n"));
		return 1;
	}
	return 0;
}

int CGbadisasm::Help() const
{
	UPrintf(USTR("gbadisasm %") PRIUS USTR(" by dnasdw\n\n"), AToU(GBATOOLS_VERSION).c_str());
	UPrintf(USTR("usage: gbadisasm [option...] [option]...\n\n"));
	UPrintf(USTR("option:\n"));
	const SOption* pOption = s_Option;
	while (pOption->Name != nullptr || pOption->Doc != nullptr)
	{
		if (pOption->Name != nullptr)
		{
			UPrintf(USTR("  "));
			if (pOption->Key != 0)
			{
				UPrintf(USTR("-%c,"), pOption->Key);
			}
			else
			{
				UPrintf(USTR("   "));
			}
			UPrintf(USTR(" --%-8") PRIUS, pOption->Name);
			if (UCslen(pOption->Name) >= 8 && pOption->Doc != nullptr)
			{
				UPrintf(USTR("\n%16") PRIUS, USTR(""));
			}
		}
		if (pOption->Doc != nullptr)
		{
			UPrintf(USTR("%") PRIUS, pOption->Doc);
		}
		UPrintf(USTR("\n"));
		pOption++;
	}
	return 0;
}

int CGbadisasm::Action() const
{
	if (m_eAction == kActionDisasm)
	{
		if (!disasmFile())
		{
			UPrintf(USTR("ERROR: disasm file failed\n\n"));
			return 1;
		}
	}
	else if (m_eAction == kActionSample)
	{
		return sample();
	}
	else if (m_eAction == kActionHelp)
	{
		return Help();
	}
	return 0;
}

CGbadisasm::EParseOptionReturn CGbadisasm::parseOptions(const UChar* a_pName, int& a_nIndex, int a_nArgc, UChar* a_pArgv[])
{
	if (UCscmp(a_pName, USTR("input")) == 0)
	{
		if (a_nIndex + 1 >= a_nArgc)
		{
			return kParseOptionReturnNoArgument;
		}
		m_sInputFileName = a_pArgv[++a_nIndex];
		if (m_eAction == kActionNone)
		{
			m_eAction = kActionDisasm;
		}
		else if (m_eAction != kActionDisasm && m_eAction != kActionHelp)
		{
			return kParseOptionReturnOptionConflict;
		}
	}
	else if (UCscmp(a_pName, USTR("output")) == 0)
	{
		if (a_nIndex + 1 >= a_nArgc)
		{
			return kParseOptionReturnNoArgument;
		}
		m_sOutputFileName = a_pArgv[++a_nIndex];
	}
	else if (UCscmp(a_pName, USTR("config")) == 0)
	{
		if (a_nIndex + 1 >= a_nArgc)
		{
			return kParseOptionReturnNoArgument;
		}
		m_sConfigFileName = a_pArgv[++a_nIndex];
	}
	else if (UCscmp(a_pName, USTR("address")) == 0)
	{
		if (a_nIndex + 1 >= a_nArgc)
		{
			return kParseOptionReturnNoArgument;
		}
		UString sAddress = a_pArgv[++a_nIndex];
		if (StartWith(sAddress, USTR("0X")) || StartWith(sAddress, USTR("0x")))
		{
			if (sAddress.find_first_not_of(USTR("0123456789ABCDEFabcdef"), 2) != UString::npos)
			{
				m_sMessage = sAddress;
				return kParseOptionReturnUnknownArgument;
			}
			m_uAddress = SToU32(sAddress.c_str() + 2, 16);
		}
		else
		{
			if (sAddress.find_first_not_of(USTR("0123456789")) != UString::npos)
			{
				m_sMessage = sAddress;
				return kParseOptionReturnUnknownArgument;
			}
			m_uAddress = SToU32(sAddress);
		}
	}
	else if (UCscmp(a_pName, USTR("standalone")) == 0)
	{
		m_bStandalone = true;
	}
	else if (UCscmp(a_pName, USTR("sample")) == 0)
	{
		if (m_eAction == kActionNone)
		{
			m_eAction = kActionSample;
		}
		else if (m_eAction != kActionSample && m_eAction != kActionHelp)
		{
			return kParseOptionReturnOptionConflict;
		}
	}
	else if (UCscmp(a_pName, USTR("help")) == 0)
	{
		m_eAction = kActionHelp;
	}
	else if (UCscmp(a_pName, USTR("verbose")) == 0)
	{
		m_bVerbose = true;
	}
	return kParseOptionReturnSuccess;
}

CGbadisasm::EParseOptionReturn CGbadisasm::parseOptions(int a_nKey, int& a_nIndex, int a_nArgc, UChar* a_pArgv[])
{
	for (const SOption* pOption = s_Option; pOption->Name != nullptr || pOption->Key != 0 || pOption->Doc != nullptr; pOption++)
	{
		if (pOption->Key == a_nKey)
		{
			return parseOptions(pOption->Name, a_nIndex, a_nArgc, a_pArgv);
		}
	}
	return kParseOptionReturnIllegalOption;
}

bool CGbadisasm::disasmFile() const
{
	CDisasm disasm;
	disasm.SetInputFileName(m_sInputFileName);
	disasm.SetOutputFileName(m_sOutputFileName);
	disasm.SetConfigFileName(m_sConfigFileName);
	disasm.SetAddress(m_uAddress);
	disasm.SetStandalone(m_bStandalone);
	disasm.SetVerbose(m_bVerbose);
	bool bResult = disasm.DisasmFile();
	return bResult;
}

int CGbadisasm::sample() const
{
	UPrintf(USTR("sample:\n"));
	UPrintf(USTR("# disasm gba\n"));
	UPrintf(USTR("gbadisasm -i baserom.gba -c base.cfg -l 0x8000000\n\n"));
	UPrintf(USTR("# disasm standalone bin\n"));
	UPrintf(USTR("gbadisasm -i arm.bin -c arm.cfg -s\n\n"));
	return 0;
}

int UMain(int argc, UChar* argv[])
{
	CGbadisasm tool;
	if (tool.ParseOptions(argc, argv) != 0)
	{
		return tool.Help();
	}
	if (tool.CheckOptions() != 0)
	{
		return 1;
	}
	return tool.Action();
}
