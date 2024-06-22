#ifndef GBADISASM_H_
#define GBADISASM_H_

#include <sdw.h>

class CGbadisasm
{
public:
	enum EParseOptionReturn
	{
		kParseOptionReturnSuccess,
		kParseOptionReturnIllegalOption,
		kParseOptionReturnNoArgument,
		kParseOptionReturnUnknownArgument,
		kParseOptionReturnOptionConflict
	};
	enum EAction
	{
		kActionNone,
		kActionDisasm,
		kActionSample,
		kActionHelp
	};
	struct SOption
	{
		const UChar* Name;
		int Key;
		const UChar* Doc;
	};
	CGbadisasm();
	~CGbadisasm();
	int ParseOptions(int a_nArgc, UChar* a_pArgv[]);
	int CheckOptions() const;
	int Help() const;
	int Action() const;
	static const SOption s_Option[];
private:
	EParseOptionReturn parseOptions(const UChar* a_pName, int& a_nIndex, int a_nArgc, UChar* a_pArgv[]);
	EParseOptionReturn parseOptions(int a_nKey, int& a_nIndex, int a_nArgc, UChar* a_pArgv[]);
	bool disasmFile() const;
	int sample() const;
	EAction m_eAction;
	UString m_sInputFileName;
	UString m_sOutputFileName;
	UString m_sConfigFileName;
	u32 m_uAddress;
	bool m_bStandalone;
	bool m_bVerbose;
	UString m_sMessage;
};

#endif	// GBADISASM_H_
