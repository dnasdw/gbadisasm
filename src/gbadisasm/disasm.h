#ifndef DISASM_H_
#define DISASM_H_

#include <sdw.h>
#include <capstone.h>

enum ELabelType
{
	kLabelTypeUnknown,
	kLabelTypeArmCode,
	kLabelTypeThumbCode,
	kLabelTypeData,
	kLabelTypePool,
	kLabelTypeJumpTable
};

enum EBranchType
{
	kBranchTypeUnknown,
	kBranchTypeB,
	kBranchTypeBL
};

struct SLabel
{
	u32 Address;
	n32 Type;
	n32 BranchType;
	u32 Size;
	bool IsProcessed;
	bool IsFunc;
	// TODO: delete begin
	bool Inactive;
	bool IsFarJump;
	// TODO: delete end
	string Name;
	// TODO: delete begin
	map<u32, n32> DepAddressIndex;
	// TODO: delete end

	SLabel();
	const string& GetLabelName() const;
	const string& GetFuncStartMicro() const;
	static const u32 UnknownSize;
};

class CDisasm
{
public:
	CDisasm();
	~CDisasm();
	void SetInputFileName(const UString& a_sInputFileName);
	void SetOutputFileName(const UString& a_sOutputFileName);
	void SetConfigFileName(const UString& a_sConfigFileName);
	void SetAddress(u32 a_uAddress);
	void SetStandalone(bool a_bStandalone);
	void SetVerbose(bool a_bVerbose);
	bool DisasmFile();
private:
	static u32 getMinSize(n32 a_nLabelType);
	static u32 getAlignment(n32 a_nLabelType);
	static bool isBranch(const cs_insn* a_pInsn);
	static bool isFuncReturn(const cs_insn* a_pInsn);
	static bool isPoolLoad(const cs_insn* a_pInsn);
	bool readFile();
	bool readConfigFile();
	bool disassemble();
	bool analyze();
	bool printDisassembly();
	bool printGap(u32 a_uAddress, u32 a_uNextAddress) const;
	bool printInsn(const cs_insn* a_pInsn, n32 a_nType) const;
	n32 addLabel(u32 a_uAddress, n32 a_nType, const string& a_sName);
	bool addLabelByJumpTable(u32 a_uAddress, u32 a_uCount, n32 a_nLabelType);
	n32 addCodeLabel(u32 a_uAddressX);
	n32 getUnprocessedLabelIndex() const;
	n32 getNextLabelIndex(u32 a_uAddress) const;
	bool armJumpTableStateMachine(const cs_insn* a_pInsn);
	bool thumbJumpTableStateMachine(const cs_insn* a_pInsn);
	u32 getBranchTarget(const cs_insn* a_pInsn) const;
	u32 getPoolLoad(const cs_insn* a_pInsn, n32 a_nMode) const;
	bool getByte(u32 a_uAddress, u8& a_uValue) const;
	bool getShort(u32 a_uAddress, u16& a_uValue) const;
	bool getLong(u32 a_uAddress, u32& a_uValue) const;
	n32 getLabelIndex(u32 a_uAddress) const;
	static const n32 s_nOptionDataColumnWidth;
	static const bool s_bOptionShowAddrComments;
	UString m_sInputFileName;
	UString m_sOutputFileName;
	UString m_sConfigFileName;
	u32 m_uAddress;
	bool m_bStandalone;
	bool m_bVerbose;
	FILE* m_fp;
	u32 m_uFileSize;
	vector<u8> m_vFile;
	vector<SLabel> m_vLabel;
	set<u32> m_sUnprocessedLabelAddress;
	map<u32, n32> m_mLabelAddressIndex;
	csh m_uHandle;
	n32 m_nArmJumpTableState;
	n32 m_nThumbJumpTableState;
	cs_insn* m_pInsn;
	size_t m_uDisasmCount;
};

#endif	// DISASM_H_
