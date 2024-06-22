#include "disasm.h"

const u32 SLabel::UnknownSize = UINT32_MAX;

const n32 CDisasm::s_nOptionDataColumnWidth = 16;
const bool CDisasm::s_bOptionShowAddrComments = false;

SLabel::SLabel()
	: Address(0)
	, Type(kLabelTypeUnknown)
	, BranchType(kBranchTypeUnknown)
	, Size(UnknownSize)
	, IsProcessed(false)
	, IsFunc(false)
	// TODO: delete begin
	, Inactive(false)
	, IsFarJump(false)
	// TODO: delete end
{
}

const string& SLabel::GetLabelName() const
{
	static string c_sLabelName = "";
	if (!Name.empty())
	{
		c_sLabelName = Name;
	}
	else
	{
		c_sLabelName = Format("%s_%08X", (BranchType == kBranchTypeBL ? "sub" : ""), Address);
	}
	return c_sLabelName;
}

const string& SLabel::GetFuncStartMicro() const
{
	static const string c_sFuncStartNull = "";
	static const string c_sFuncStartArm = "arm_func_start";
	static const string c_sFuncStartThumb = "thumb_func_start";
	static const string c_sFuncStartThumbNonWordAligned = "non_word_aligned_thumb_func_start";
	if (BranchType == kBranchTypeBL)
	{
		if (Type == kLabelTypeArmCode)
		{
			return c_sFuncStartArm;
		}
		else if (Type == kLabelTypeThumbCode)
		{
			if (Address % 4 == 0)
			{
				return c_sFuncStartThumb;
			}
			else
			{
				return c_sFuncStartThumbNonWordAligned;
			}
		}
	}
	return c_sFuncStartNull;
}

CDisasm::CDisasm()
	: m_uAddress(0x08000000)
	, m_bStandalone(false)
	, m_bVerbose(false)
	, m_fp(nullptr)
	, m_uFileSize(0)
	, m_uHandle(0)
	, m_nArmJumpTableState(0)
	, m_nThumbJumpTableState(0)
	, m_pInsn(nullptr)
	, m_uDisasmCount(0)
{
}

CDisasm::~CDisasm()
{
	if (m_fp != nullptr)
	{
		fclose(m_fp);
		m_fp = nullptr;
	}
	if (m_pInsn != nullptr)
	{
		cs_free(m_pInsn, m_uDisasmCount);
		m_pInsn = nullptr;
	}
	if (m_uHandle != 0)
	{
		cs_close(&m_uHandle);
		m_uHandle = 0;
	}
}

void CDisasm::SetInputFileName(const UString& a_sInputFileName)
{
	m_sInputFileName = a_sInputFileName;
}

void CDisasm::SetOutputFileName(const UString& a_sOutputFileName)
{
	m_sOutputFileName = a_sOutputFileName;
}

void CDisasm::SetConfigFileName(const UString& a_sConfigFileName)
{
	m_sConfigFileName = a_sConfigFileName;
}

void CDisasm::SetAddress(u32 a_uAddress)
{
	m_uAddress = a_uAddress;
}

void CDisasm::SetStandalone(bool a_bStandalone)
{
	m_bStandalone = a_bStandalone;
}

void CDisasm::SetVerbose(bool a_bVerbose)
{
	m_bVerbose = a_bVerbose;
}

bool CDisasm::DisasmFile()
{
	bool bResult = readFile();
	if (!bResult)
	{
		return false;
	}
	bResult = readConfigFile();
	if (!bResult)
	{
		return false;
	}
	bResult = disassemble();
	return bResult;
}

u32 CDisasm::getMinSize(n32 a_nLabelType)
{
	switch (a_nLabelType)
	{
	case kLabelTypeArmCode:
	case kLabelTypePool:
	case kLabelTypeJumpTable:
		return 4;
	case kLabelTypeThumbCode:
		return 2;
	case kLabelTypeData:
	default:
		return 1;
	}
}

u32 CDisasm::getAlignment(n32 a_nLabelType)
{
	switch (a_nLabelType)
	{
	case kLabelTypeArmCode:
	case kLabelTypePool:
	case kLabelTypeJumpTable:
		return 4;
	case kLabelTypeThumbCode:
		return 2;
	case kLabelTypeData:
	default:
		return 1;
	}
}

bool CDisasm::isBranch(const cs_insn* a_pInsn)
{
	if (a_pInsn == nullptr)
	{
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return false;
	}
	switch (a_pInsn->id)
	{
	case ARM_INS_B:
	case ARM_INS_BL:
	case ARM_INS_BX:
		return true;
	default:
		return false;
	}
}

bool CDisasm::isFuncReturn(const cs_insn* a_pInsn)
{
	if (a_pInsn == nullptr)
	{
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return false;
	}
	const cs_arm* pArm = &a_pInsn->detail->arm;
	if (pArm->op_count < 1)
	{
		return false;
	}
	if (a_pInsn->id == ARM_INS_BX)
	{
		return pArm->cc == ARM_CC_AL;
	}
	else if (a_pInsn->id == ARM_INS_MOV)
	{
		const cs_arm_op* pArmOp0 = &pArm->operands[0];
		if (pArmOp0->type == ARM_OP_REG && pArmOp0->reg == ARM_REG_PC)
		{
			return true;
		}
	}
	else if (a_pInsn->id == ARM_INS_POP)
	{
		for (n32 i = 0; i < pArm->op_count; i++)
		{
			const cs_arm_op* pArmOp = &pArm->operands[i];
			if (pArmOp->type == ARM_OP_REG && pArmOp->reg == ARM_REG_PC)
			{
				return true;
			}
		}
	}
	return false;
}

bool CDisasm::isPoolLoad(const cs_insn* a_pInsn)
{
	if (a_pInsn == nullptr)
	{
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return false;
	}
	const cs_arm* pArm = &a_pInsn->detail->arm;
	if (a_pInsn->id == ARM_INS_LDR && pArm->op_count == 2)
	{
		const cs_arm_op* pArmOp0 = &pArm->operands[0];
		const cs_arm_op* pArmOp1 = &pArm->operands[1];
		// TODO: delete begin
		if (pArmOp1->subtracted)
		{
			int a = 1;
		}
		// TODO: delete end
		if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_MEM)
		{
			const arm_op_mem* pArmOp1Mem = &pArmOp1->mem;
			if (pArmOp1Mem->base == ARM_REG_PC && pArmOp1Mem->index == ARM_REG_INVALID)
			{
				return true;
			}
		}
	}
	return false;
}

bool CDisasm::readFile()
{
	if (m_sInputFileName.empty())
	{
		UPrintf(USTR("ERROR: input file name is empty\n\n"));
		return false;
	}
	m_fp = UFopen(m_sInputFileName, USTR("rb"), true);
	if (m_fp == nullptr)
	{
		return false;
	}
	Fseek(m_fp, 0, SEEK_END);
	m_uFileSize = static_cast<u32>(Ftell(m_fp));
	if (m_uFileSize < 2)
	{
		fclose(m_fp);
		m_fp = nullptr;
		UPrintf(USTR("ERROR: file '%") PRIUS USTR("' is too small\n\n"), m_sInputFileName.c_str());
		return false;
	}
	m_vFile.resize(m_uFileSize);
	Fseek(m_fp, 0, SEEK_SET);
	fread(&*m_vFile.begin(), 1, m_uFileSize, m_fp);
	fclose(m_fp);
	m_fp = nullptr;
	return true;
}

static bool empty(const string& a_sString)
{
	return a_sString.empty();
}

bool CDisasm::readConfigFile()
{
	if (m_sConfigFileName.empty())
	{
		UPrintf(USTR("ERROR: config file name is empty\n\n"));
		return false;
	}
	m_fp = UFopen(m_sConfigFileName, USTR("rb"), true);
	if (m_fp == nullptr)
	{
		return false;
	}
	Fseek(m_fp, 0, SEEK_END);
	u32 uFileSize = static_cast<u32>(Ftell(m_fp));
	Fseek(m_fp, 0, SEEK_SET);
	char* pTemp = new char[uFileSize + 1];
	fread(pTemp, 1, uFileSize, m_fp);
	fclose(m_fp);
	m_fp = nullptr;
	pTemp[uFileSize] = 0;
	string sConfig = pTemp;
	delete[] pTemp;
	sConfig = Replace(sConfig, "\r\n", "\n");
	sConfig = Replace(sConfig, "\r", "\n");
	vector<string> vText = Split(sConfig, "\n");
	n32 nLineCount = static_cast<n32>(vText.size());
	for (n32 nLineNumber = 0; nLineNumber < nLineCount; nLineNumber++)
	{
		const string& sLine = vText[nLineNumber];
		string sTrimmedLine = Trim(sLine);
		if (sTrimmedLine.empty() || StartWith(sTrimmedLine, "#"))
		{
			continue;
		}
		vector<string> vLine = SplitOf(sTrimmedLine, " \t");
		vector<string>::const_iterator itLine = remove_if(vLine.begin(), vLine.end(), empty);
		vLine.erase(itLine, vLine.end());
		if (vLine.empty())
		{
			continue;
		}
		if (vLine.size() < 2)
		{
			UPrintf(USTR("ERROR: %") PRIUS USTR(": syntax error on line %d: %") PRIUS USTR("\n\n"), m_sConfigFileName.c_str(), nLineNumber + 1, AToU(sLine).c_str());
			return false;
		}
		const string& sType = vLine[0];
		const string& sAddress = vLine[1];
		u32 uAddress = 0;
		if (StartWith(sAddress, "0X") || StartWith(sAddress, "0x"))
		{
			uAddress = SToU32(sAddress.c_str() + 2, 16);
		}
		else
		{
			uAddress = SToU32(sAddress);
		}
		if (uAddress < m_uAddress || uAddress >= m_uAddress + m_uFileSize)
		{
			if (m_bVerbose)
			{
				fprintf(stderr, "WARNING: %s: address 0x%08X is out of range [0x%08X, 0x%08X)\n", UToA(m_sConfigFileName).c_str(), uAddress, m_uAddress, m_uAddress + m_uFileSize);
			}
			continue;
		}
		string sName = "";
		if (vLine.size() > 2)
		{
			sName = vLine[2];
		}
		bool bForceFunc = false;
		if (vLine.size() > 3)
		{
			bForceFunc = true;
		}
		if (sType == "arm_func")
		{
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeArmCode, sName);
			if (nLabelIndex < 0)
			{
				return false;
			}
			if (bForceFunc)
			{
				m_vLabel[nLabelIndex].IsFunc = true;
			}
		}
		else if (sType == "thumb_func")
		{
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeThumbCode, sName);
			if (nLabelIndex < 0)
			{
				return false;
			}
			if (bForceFunc)
			{
				m_vLabel[nLabelIndex].IsFunc = true;
			}
		}
		else if (sType == "arm_label")
		{
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeArmCode, sName);
			if (nLabelIndex < 0)
			{
				return false;
			}
			m_vLabel[nLabelIndex].BranchType = kBranchTypeB;
		}
		else if (sType == "thumb_label")
		{
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeThumbCode, sName);
			if (nLabelIndex < 0)
			{
				return false;
			}
			m_vLabel[nLabelIndex].BranchType = kBranchTypeB;
		}
		// TODO: delete begin
		else if (sType == "arm_far_jump")
		{
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeArmCode, sName);
			if (nLabelIndex < 0)
			{
				return false;
			}
			m_vLabel[nLabelIndex].BranchType = kBranchTypeB;
			m_vLabel[nLabelIndex].IsFarJump = true;
		}
		else if (sType == "thumb_far_jump")
		{
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeThumbCode, sName);
			if (nLabelIndex < 0)
			{
				return false;
			}
			m_vLabel[nLabelIndex].BranchType = kBranchTypeB;
			m_vLabel[nLabelIndex].IsFarJump = true;
		}
		// TODO: delete end
		else if (sType == "data_label")
		{
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeData, "");
			if (nLabelIndex < 0)
			{
				return false;
			}
		}
		else if (sType == "pool_label")
		{
			if (vLine.size() < 3)
			{
				UPrintf(USTR("ERROR: required count is missing\n\n"));
				UPrintf(USTR("ERROR: %") PRIUS USTR(": syntax error on line %d: %") PRIUS USTR("\n\n"), m_sConfigFileName.c_str(), nLineNumber + 1, AToU(sLine).c_str());
				return false;
			}
			const string& sCount = vLine[2];
			u32 uCount = 0;
			if (StartWith(sCount, "0X") || StartWith(sCount, "0x"))
			{
				uCount = SToU32(sCount.c_str() + 2, 16);
			}
			else
			{
				uCount = SToU32(sCount);
			}
			if (uCount < 1)
			{
				UPrintf(USTR("ERROR: count %u is invalid\n\n"), uCount);
				UPrintf(USTR("ERROR: %") PRIUS USTR(": syntax error on line %d: %") PRIUS USTR("\n\n"), m_sConfigFileName.c_str(), nLineNumber + 1, AToU(sLine).c_str());
				return false;
			}
			for (u32 i = 0; i < uCount; i++)
			{
				u32 uPoolAddress = uAddress + i * 4;
				const n32 nLabelIndex = addLabel(uPoolAddress, kLabelTypePool, "");
				if (nLabelIndex < 0)
				{
					return false;
				}
			}
		}
		else if (sType == "jump_table")
		{
			if (vLine.size() < 3)
			{
				UPrintf(USTR("ERROR: required count is missing\n\n"));
				UPrintf(USTR("ERROR: %") PRIUS USTR(": syntax error on line %d: %") PRIUS USTR("\n\n"), m_sConfigFileName.c_str(), nLineNumber + 1, AToU(sLine).c_str());
				return false;
			}
			const string& sCount = vLine[2];
			u32 uCount = 0;
			if (StartWith(sCount, "0X") || StartWith(sCount, "0x"))
			{
				uCount = SToU32(sCount.c_str() + 2, 16);
			}
			else
			{
				uCount = SToU32(sCount);
			}
			if (uCount < 1)
			{
				UPrintf(USTR("ERROR: count %u is invalid\n\n"), uCount);
				UPrintf(USTR("ERROR: %") PRIUS USTR(": syntax error on line %d: %") PRIUS USTR("\n\n"), m_sConfigFileName.c_str(), nLineNumber + 1, AToU(sLine).c_str());
				return false;
			}
			n32 nLabelType = kLabelTypeUnknown;
			if (vLine.size() > 3)
			{
				const string& sLabelType = vLine[3];
				if (strcasecmp(sLabelType.c_str(), "arm") == 0)
				{
					nLabelType = kLabelTypeArmCode;
				}
				else if (strcasecmp(sLabelType.c_str(), "thumb") == 0)
				{
					nLabelType = kLabelTypeThumbCode;
				}
				else
				{
					UPrintf(USTR("ERROR: label type '%") PRIUS USTR("' is invalid\n\n"), AToU(sLabelType).c_str());
					UPrintf(USTR("ERROR: %") PRIUS USTR(": syntax error on line %d: %") PRIUS USTR("\n\n"), m_sConfigFileName.c_str(), nLineNumber + 1, AToU(sLine).c_str());
					return false;
				}
			}
			const n32 nLabelIndex = addLabel(uAddress, kLabelTypeJumpTable, "");
			if (nLabelIndex < 0)
			{
				return false;
			}
			if (!addLabelByJumpTable(uAddress, uCount, nLabelType))
			{
				UPrintf(USTR("ERROR: %") PRIUS USTR(": syntax error on line %d: %") PRIUS USTR("\n\n"), m_sConfigFileName.c_str(), nLineNumber + 1, AToU(sLine).c_str());
				return false;
			}
		}
		else
		{
			if (m_bVerbose)
			{
				fprintf(stderr, "WARNING: %s: unrecognized command '%s' on line %d: %s\n", UToA(m_sConfigFileName).c_str(), sType.c_str(), nLineNumber + 1, sLine.c_str());
			}
		}
	}
	return true;
}

bool CDisasm::disassemble()
{
	if (!m_bStandalone)
	{
		addLabel(m_uAddress, kLabelTypeArmCode, "_start");
	}
	if (m_vLabel.empty())
	{
		UPrintf(USTR("ERROR: you need to at least provide one code label in the cfg to startwith\n\n"));
		return false;
	}
	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &m_uHandle) != CS_ERR_OK)
	{
		UPrintf(USTR("ERROR: open arm handle failed\n\n"));
		return false;
	}
	// TODO: uncomment begin
	//cs_option(m_uHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	// TODO: uncomment end
	cs_option(m_uHandle, CS_OPT_DETAIL, CS_OPT_ON);
	bool bResult = analyze();
	if (!bResult)
	{
		cs_close(&m_uHandle);
		m_uHandle = 0;
		return false;
	}
	bResult = printDisassembly();
	cs_close(&m_uHandle);
	m_uHandle = 0;
	return bResult;
}

bool CDisasm::analyze()
{
	bool bResult = true;
	while (bResult)
	{
		const n32 nLabelIndex = getUnprocessedLabelIndex();
		if (nLabelIndex < 0)
		{
			// TODO: uncomment begin
			//break;
			// TODO: uncomment end
			// TODO: delete begin
			bool bBreak = true;
			for (map<u32, n32>::const_iterator it = m_mLabelAddressIndex.begin(); it != m_mLabelAddressIndex.end(); ++it)
			{
				n32 nTestLabelIndex = it->second;
				if (!m_vLabel[nTestLabelIndex].Inactive && !m_vLabel[nTestLabelIndex].DepAddressIndex.empty())
				{
					if (false)
					{
						for (map<u32, n32>::const_iterator itCurr = it; itCurr != m_mLabelAddressIndex.begin(); --itCurr)
						{
							map<u32, n32>::const_iterator itPrev = itCurr;
							--itPrev;
							n32 nPrevCodeLabelIndex = itPrev->second;
							if ((m_vLabel[nPrevCodeLabelIndex].Type == kLabelTypeArmCode || m_vLabel[nPrevCodeLabelIndex].Type == kLabelTypeThumbCode) && !m_vLabel[nPrevCodeLabelIndex].Inactive)
							{
								m_vLabel[nPrevCodeLabelIndex].IsProcessed = false;
								break;
							}
						}
						m_vLabel[nTestLabelIndex].Inactive = true;
						m_sUnprocessedLabelAddress.erase(m_vLabel[nTestLabelIndex].Address);
					}
				}
			}
			if (bBreak)
			{
				break;
			}
			// TODO: delete end
		}
		u32 uAddress = m_vLabel[nLabelIndex].Address;
		n32 nType = m_vLabel[nLabelIndex].Type;
		if (nType == kLabelTypeArmCode)
		{
			cs_option(m_uHandle, CS_OPT_MODE, CS_MODE_ARM);
		}
		else if (nType == kLabelTypeThumbCode)
		{
			cs_option(m_uHandle, CS_OPT_MODE, CS_MODE_THUMB);
		}
		if (nType == kLabelTypeArmCode || nType == kLabelTypeThumbCode)
		{
			if (m_bVerbose)
			{
				fprintf(stderr, "analyzing label at 0x%08X\n", uAddress);
			}
			const n32 nNextLabelIndex0 = getNextLabelIndex(uAddress);
			// TODO: delete begin
			map<u32, n32> mProcessedCallsInChunkAddressIndex;
			// TODO: delete end
			u32 uAddressMax = nNextLabelIndex0 >= 0 ? m_vLabel[nNextLabelIndex0].Address : m_uAddress + m_uFileSize;
			u32 uFileOffset = uAddress - m_uAddress;
			u32 uCodeSize = uAddressMax - uAddress;
			m_nArmJumpTableState = 0;
			m_nThumbJumpTableState = 0;
			m_uDisasmCount = cs_disasm(m_uHandle, &*m_vFile.begin() + uFileOffset, uCodeSize, uAddress, 0, &m_pInsn);
			for (size_t i = 0; i < m_uDisasmCount; i++)
			{
				const cs_insn* pInsn = m_pInsn + i;
				if (pInsn->address != uAddress)
				{
					UPrintf(USTR("ERROR: address 0x%08X does not match expected address 0x%08X\n\n"), static_cast<u32>(pInsn->address), uAddress);
					bResult = false;
					break;
				}
				const n32 nNextLabelIndex1 = getNextLabelIndex(uAddress);
				if (nNextLabelIndex1 >= 0 && m_vLabel[nNextLabelIndex1].Address < uAddressMax)
				{
					uAddressMax = m_vLabel[nNextLabelIndex1].Address;
				}
				if (uAddress + pInsn->size > uAddressMax)
				{
					break;
				}
				if (nType == kLabelTypeThumbCode && cs_insn_group(m_uHandle, pInsn, ARM_GRP_THUMB2))
				{
					if (m_bVerbose)
					{
						fprintf(stderr, "WARNING: thumb2 instruction /*0x%08X*/ %s %s\n", uAddress, pInsn->mnemonic, pInsn->op_str);
					}
					break;
				}
				if (m_bVerbose)
				{
					fprintf(stderr, "/*0x%08X*/ %s %s\n", uAddress, pInsn->mnemonic, pInsn->op_str);
				}
				if (cs_insn_group(m_uHandle, pInsn, ARM_GRP_ARM))
				{
					m_nThumbJumpTableState = 0;
					if (!armJumpTableStateMachine(pInsn))
					{
						if (m_bVerbose)
						{
							fprintf(stderr, "WARNING: arm jump table state machine failed /*0x%08X*/ %s %s\n", uAddress, pInsn->mnemonic, pInsn->op_str);
						}
						break;
					}
				}
				else if (cs_insn_group(m_uHandle, pInsn, ARM_GRP_THUMB))
				{
					m_nArmJumpTableState = 0;
					if (!thumbJumpTableStateMachine(pInsn))
					{
						if (m_bVerbose)
						{
							fprintf(stderr, "WARNING: thumb jump table state machine failed /*0x%08X*/ %s %s\n", uAddress, pInsn->mnemonic, pInsn->op_str);
						}
						break;
					}
				}
				uAddress += pInsn->size;
				const cs_arm* pArm = &pInsn->detail->arm;
				if (isBranch(pInsn))
				{
					if (pInsn->id == ARM_INS_BX && pArm->op_count == 1 && nType == kLabelTypeThumbCode)
					{
						const cs_arm_op* pArmOp0 = &pArm->operands[0];
						if (pArmOp0->type == ARM_OP_REG && pArmOp0->reg == ARM_REG_PC)
						{
							u32 uTargetAddressX = static_cast<u32>((pInsn->address & ~0x3uLL) + 4);
							addCodeLabel(uTargetAddressX);
							break;
						}
					}
					if (isFuncReturn(pInsn))
					{
						if (pInsn->id == ARM_INS_BX && pArm->op_count == 1 && i > 0)
						{
							const cs_arm_op* pArmOp0 = &pArm->operands[0];
							const cs_insn* pPrevInsn = m_pInsn + i - 1;
							const cs_arm* pPrevArm = &pPrevInsn->detail->arm;
							if (pPrevInsn->id == ARM_INS_MOV && pPrevArm->op_count == 2)
							{
								const cs_arm_op* pPrevArmOp0 = &pPrevArm->operands[0];
								const cs_arm_op* pPrevArmOp1 = &pPrevArm->operands[1];
								if (pPrevArmOp0->type == ARM_OP_REG && pPrevArmOp1->type == ARM_OP_REG && pArmOp0->type == ARM_OP_REG && pPrevArmOp0->reg == ARM_REG_LR && pPrevArmOp1->reg == ARM_REG_PC && pArmOp0->reg != pPrevArmOp0->reg)
								{
									// TODO: delete begin
									if (nType == kLabelTypeThumbCode)
									{
										int a = 1;
									}
									// TODO: delete end
									continue;
								}
							}
							else if (nType == kLabelTypeArmCode && pPrevInsn->id == ARM_INS_ADD && pPrevArm->op_count == 3)
							{
								const cs_arm_op* pPrevArmOp0 = &pPrevArm->operands[0];
								const cs_arm_op* pPrevArmOp1 = &pPrevArm->operands[1];
								const cs_arm_op* pPrevArmOp2 = &pPrevArm->operands[2];
								if (pPrevArmOp0->type == ARM_OP_REG && pPrevArmOp1->type == ARM_OP_REG && pPrevArmOp2->type == ARM_OP_IMM && pPrevArmOp0->reg == ARM_REG_LR && pPrevArmOp1->reg == ARM_REG_PC && pArmOp0->reg != pPrevArmOp0->reg && pPrevArmOp2->imm == 0)
								{
									continue;
								}
							}
						}
						// TODO: delete begin
						if (nNextLabelIndex1 >= 0 && m_vLabel[nNextLabelIndex1].Address == uAddress && (m_vLabel[nNextLabelIndex1].Type == kLabelTypeArmCode || m_vLabel[nNextLabelIndex1].Type == kLabelTypeThumbCode) && m_vLabel[nNextLabelIndex1].Type != nType && m_vLabel[nNextLabelIndex1].BranchType == kBranchTypeB)
						{
							m_vLabel[nNextLabelIndex1].BranchType = kBranchTypeBL;
							m_vLabel[nNextLabelIndex1].IsFunc = true;
						}
						// TODO: delete end
						break;
					}
					if (pInsn->id == ARM_INS_BX && pArm->cc != ARM_CC_AL)
					{
						continue;
					}
					u32 uTargetAddress = getBranchTarget(pInsn);
					if (uTargetAddress < m_uAddress || uTargetAddress >= m_uAddress + m_uFileSize)
					{
						uAddress -= pInsn->size;
						if (m_bVerbose)
						{
							fprintf(stderr, "WARNING: branch target 0x%08X is out of range [0x%08X, 0x%08X)\n", uTargetAddress, m_uAddress, m_uAddress + m_uFileSize);
						}
						break;
					}
					const n32 nTargetLabelIndex = addLabel(uTargetAddress, nType, "");
					if (nTargetLabelIndex < 0)
					{
						bResult = false;
						break;
					}
					if (!m_vLabel[nTargetLabelIndex].IsFunc)
					{
						if (pInsn->id == ARM_INS_BL)
						{
							if (m_vLabel[nTargetLabelIndex].BranchType != kBranchTypeB)
							{
								m_vLabel[nTargetLabelIndex].BranchType = kBranchTypeBL;
								// TODO: delete begin
								mProcessedCallsInChunkAddressIndex[uTargetAddress] = nTargetLabelIndex;
								// TODO: delete end
							}
							// TODO: delete begin
							else if (pArm->cc == ARM_CC_AL && m_vLabel[nTargetLabelIndex].IsFarJump)
							{
								break;
							}
							// TODO: delete end
							u16 uPadding = 0;
							if ((nNextLabelIndex1 >= 0 && m_vLabel[nNextLabelIndex1].Address == uAddress && m_vLabel[nNextLabelIndex1].Type == kLabelTypePool) || (uAddress % 4 == 2 && getShort(uAddress, uPadding) && uPadding == 0))
							{
								// TODO: delete begin
								m_vLabel[nTargetLabelIndex].IsFarJump = true;
								// TODO: delete end
								m_vLabel[nTargetLabelIndex].BranchType = kBranchTypeB;
								// TODO: delete begin
								for (map<u32, n32>::const_iterator it = m_mLabelAddressIndex.begin(); it != m_mLabelAddressIndex.end(); ++it)
								{
									n32 nTestLabelIndex = it->second;
									// TODO: delete begin
									if (m_vLabel[nTestLabelIndex].DepAddressIndex.find(uTargetAddress) != m_vLabel[nTestLabelIndex].DepAddressIndex.end())
									{
										m_vLabel[nTestLabelIndex].DepAddressIndex.erase(uTargetAddress);
									}
									// TODO: delete end
									m_vLabel[nTestLabelIndex].DepAddressIndex.erase(uTargetAddress);
								}
								// TODO: delete end
								break;
							}
						}
						else
						{
							m_vLabel[nTargetLabelIndex].BranchType = kBranchTypeB;
							m_vLabel[nTargetLabelIndex].Name.clear();
						}
					}
					if (pInsn->id != ARM_INS_BL && pArm->cc == ARM_CC_AL)
					{
						break;
					}
				}
				else
				{
					if (isFuncReturn(pInsn))
					{
						// TODO: delete begin
						if (nNextLabelIndex1 >= 0 && m_vLabel[nNextLabelIndex1].Address == uAddress && (m_vLabel[nNextLabelIndex1].Type == kLabelTypeArmCode || m_vLabel[nNextLabelIndex1].Type == kLabelTypeThumbCode) && m_vLabel[nNextLabelIndex1].Type != nType && m_vLabel[nNextLabelIndex1].BranchType == kBranchTypeB)
						{
							m_vLabel[nNextLabelIndex1].BranchType = kBranchTypeBL;
							m_vLabel[nNextLabelIndex1].IsFunc = true;
						}
						// TODO: delete end
						break;
					}
					u32 uTargetAddressX = 0;
					bool bCheckTarget = false;
					if (nType == kLabelTypeThumbCode && pInsn->id == ARM_INS_ADR && pArm->op_count == 2)
					{
						const cs_arm_op* pArmOp0 = &pArm->operands[0];
						const cs_arm_op* pArmOp1 = &pArm->operands[1];
						if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_IMM)
						{
							uTargetAddressX = static_cast<u32>((pInsn->address & ~0x3uLL) + pArmOp1->imm + 4);
							bCheckTarget = true;
						}
					}
					else if (nType == kLabelTypeArmCode && pInsn->id == ARM_INS_ADD && pArm->op_count == 3)
					{
						const cs_arm_op* pArmOp0 = &pArm->operands[0];
						const cs_arm_op* pArmOp1 = &pArm->operands[1];
						const cs_arm_op* pArmOp2 = &pArm->operands[2];
						if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_REG && pArmOp2->type == ARM_OP_IMM && pArmOp1->reg == ARM_REG_PC)
						{
							uTargetAddressX = static_cast<u32>((pInsn->address & ~0x3uLL) + pArmOp2->imm + 8);
							bCheckTarget = true;
						}
					}
					else if (isPoolLoad(pInsn))
					{
						u32 uPoolAddress = getPoolLoad(pInsn, nType);
						if (uPoolAddress == 0)
						{
							bResult = false;
							break;
						}
						// TODO: delete begin
						bool bFoundFarJump = false;
						for (map<u32, n32>::const_iterator itTargetLabel = mProcessedCallsInChunkAddressIndex.begin(); itTargetLabel != mProcessedCallsInChunkAddressIndex.end(); ++itTargetLabel)
						{
							u32 uTargetLabelAddress = itTargetLabel->first;
							map<u32, n32>::const_iterator it = m_mLabelAddressIndex.find(uTargetLabelAddress);
							if (it != m_mLabelAddressIndex.end())
							{
								n32 nTargetLabelIndex = it->second;
								if (m_vLabel[nTargetLabelIndex].IsFarJump)
								{
									bFoundFarJump = true;
									break;
								}
							}
						}
						if (bFoundFarJump)
						{
							continue;
						}
						// TODO: delete end
						const n32 nPoolLabelIndex = addLabel(uPoolAddress, kLabelTypePool, "");
						if (nPoolLabelIndex < 0)
						{
							bResult = false;
							break;
						}
						// TODO: delete begin
						m_vLabel[nPoolLabelIndex].Inactive = false;
						m_vLabel[nPoolLabelIndex].DepAddressIndex.insert(mProcessedCallsInChunkAddressIndex.begin(), mProcessedCallsInChunkAddressIndex.end());
						// TODO: delete end
						if (!getLong(uPoolAddress, uTargetAddressX))
						{
							bResult = false;
							break;
						}
						bCheckTarget = true;
					}
					if (bCheckTarget && uTargetAddressX % 4 != 2 && i + 1 < m_uDisasmCount)
					{
						u32 uTargetAddress = uTargetAddressX & ~0x1;
						n32 nTargetType = uTargetAddressX % 4 == 0 ? kLabelTypeArmCode : kLabelTypeThumbCode;
						u32 uMinSize = getMinSize(nTargetType);
						if (uTargetAddress >= m_uAddress && uTargetAddress + uMinSize <= m_uAddress + m_uFileSize)
						{
							const cs_insn* pNextInsn = m_pInsn + i + 1;
							const cs_arm* pNextArm = &pNextInsn->detail->arm;
							if (pNextInsn->id == ARM_INS_BX && pNextArm->op_count == 1)
							{
								const cs_arm_op* pArmOp0 = &pArm->operands[0];
								const cs_arm_op* pNextArmOp0 = &pNextArm->operands[0];
								if (pNextArmOp0->type == ARM_OP_REG)
								{
									if (pNextArmOp0->reg == pArmOp0->reg && pArmOp0->reg != ARM_REG_LR)
									{
										const n32 nTargetLabelIndex = addCodeLabel(uTargetAddressX);
										if (nTargetLabelIndex < 0)
										{
											bResult = false;
											break;
										}
									}
									else if (pNextArmOp0->reg != pArmOp0->reg && pArmOp0->reg == ARM_REG_LR)
									{
										const n32 nReturnLabelIndex = addLabel(uTargetAddress, nType, "");
										if (nReturnLabelIndex < 0)
										{
											bResult = false;
											break;
										}
										m_vLabel[nReturnLabelIndex].BranchType = kBranchTypeB;
									}
								}
							}
						}
					}
				}
			}
			cs_free(m_pInsn, m_uDisasmCount);
			m_pInsn = nullptr;
			m_uDisasmCount = 0;
			if (!bResult)
			{
				break;
			}
			m_vLabel[nLabelIndex].Size = uAddress - m_vLabel[nLabelIndex].Address;
		}
		m_vLabel[nLabelIndex].IsProcessed = true;
		m_sUnprocessedLabelAddress.erase(m_vLabel[nLabelIndex].Address);
	}
	return bResult;
}

bool CDisasm::printDisassembly()
{
	if (!m_sOutputFileName.empty())
	{
		m_fp = UFopen(m_sOutputFileName, USTR("wb"), true);
		if (m_fp == nullptr)
		{
			return false;
		}
	}
	FILE* fp = m_fp;
	if (fp == nullptr)
	{
		fp = stdout;
	}
	u32 uAddress = m_uAddress;
	bool bResult = true;
	for (map<u32, n32>::const_iterator it = m_mLabelAddressIndex.begin(); it != m_mLabelAddressIndex.end(); ++it)
	{
		const n32 nLabelIndex = it->second;
		// TODO: delete begin
		if (m_vLabel[nLabelIndex].Inactive)
		{
			continue;
		}
		// TODO: delete end
		if (uAddress > m_vLabel[nLabelIndex].Address)
		{
			UPrintf(USTR("ERROR: address 0x%08X overlaps with previous label\n\n"), m_vLabel[nLabelIndex].Address);
			bResult = false;
			break;
		}
		if (uAddress != m_vLabel[nLabelIndex].Address)
		{
			if (!printGap(uAddress, m_vLabel[nLabelIndex].Address))
			{
				bResult = false;
				break;
			}
			uAddress = m_vLabel[nLabelIndex].Address;
		}
		const n32 nNextLabelIndex = getNextLabelIndex(uAddress);
		if (nNextLabelIndex >= 0)
		{
			// TODO: delete begin
			if ((m_vLabel[nLabelIndex].Type == kLabelTypeArmCode && m_vLabel[nNextLabelIndex].Type == kLabelTypeThumbCode) || (m_vLabel[nLabelIndex].Type == kLabelTypeThumbCode && m_vLabel[nNextLabelIndex].Type == kLabelTypeArmCode))
			{
				m_vLabel[nNextLabelIndex].BranchType = kBranchTypeBL;
			}
			// TODO: delete end
			if (m_vLabel[nLabelIndex].Size == SLabel::UnknownSize || uAddress + m_vLabel[nLabelIndex].Size > m_vLabel[nNextLabelIndex].Address)
			{
				m_vLabel[nLabelIndex].Size = m_vLabel[nNextLabelIndex].Address - uAddress;
			}
		}
		n32 nType = m_vLabel[nLabelIndex].Type;
		u32 uAlignment = getAlignment(nType);
		if (uAddress % uAlignment != 0)
		{
			UPrintf(USTR("ERROR: address 0x%08X is not aligned\n\n"), uAddress);
			bResult = false;
			break;
		}
		switch (nType)
		{
		case kLabelTypeArmCode:
		case kLabelTypeThumbCode:
			{
				const string& sLabelName = m_vLabel[nLabelIndex].GetLabelName();
				if (m_vLabel[nLabelIndex].BranchType == kBranchTypeBL)
				{
					const string& sFuncStartMicro = m_vLabel[nLabelIndex].GetFuncStartMicro();
					fprintf(fp, "\n\t%s %s\n", sFuncStartMicro.c_str(), sLabelName.c_str());
					fprintf(fp, "%s: @ 0x%08X\n", sLabelName.c_str(), uAddress);
				}
				else
				{
					fprintf(fp, "%s:\n", sLabelName.c_str());
				}
				// TODO: delete begin
				if (m_vLabel[nLabelIndex].Size == SLabel::UnknownSize)
				{
					bResult = false;
					break;
				}
				// TODO: delete end
				if (nType == kLabelTypeArmCode)
				{
					cs_option(m_uHandle, CS_OPT_MODE, CS_MODE_ARM);
				}
				else if (nType == kLabelTypeThumbCode)
				{
					cs_option(m_uHandle, CS_OPT_MODE, CS_MODE_THUMB);
				}
				u32 uFileOffset = uAddress - m_uAddress;
				m_uDisasmCount = cs_disasm(m_uHandle, &*m_vFile.begin() + uFileOffset, m_vLabel[nLabelIndex].Size, uAddress, 0, &m_pInsn);
				for (size_t i = 0; i < m_uDisasmCount; i++)
				{
					const cs_insn* pInsn = m_pInsn + i;
					if (!printInsn(pInsn, nType))
					{
						bResult = false;
						break;
					}
					uAddress += pInsn->size;
				}
				cs_free(m_pInsn, m_uDisasmCount);
				m_pInsn = nullptr;
				m_uDisasmCount = 0;
				if (!bResult)
				{
					break;
				}
				if (nNextLabelIndex >= 0 && m_vLabel[nNextLabelIndex].Type == kLabelTypePool)
				{
					static const u32 c_uZero = 0;
					uFileOffset = uAddress - m_uAddress;
					n32 nAddressDelta = m_vLabel[nNextLabelIndex].Address - uAddress;
					if (nAddressDelta == 0 || (nAddressDelta > 0 && nAddressDelta < 4 && memcmp(&*m_vFile.begin() + uFileOffset, &c_uZero, nAddressDelta) == 0))
					{
						fprintf(fp, "\t.align 2, 0\n");
						uAddress += nAddressDelta;
					}
				}
			}
			break;
		case kLabelTypePool:
			{
				// TODO: delete begin
				//if (m_vLabel[nLabelIndex].Size != 4)
				//{
				//	bResult = false;
				//	break;
				//}
				// TODO: delete end
				u32 uLong = 0;
				if (!getLong(uAddress, uLong))
				{
					bResult = false;
					break;
				}
				bool bPrint = false;
				if (!bPrint && uLong % 4 != 2)
				{
					u32 uTargetAddress = uLong & ~0x1;
					n32 nTargetType = uLong % 4 == 0 ? kLabelTypeArmCode : kLabelTypeThumbCode;
					u32 uMinSize = getMinSize(nTargetType);
					const n32 nTargetLabelIndex = getLabelIndex(uTargetAddress);
					if (nTargetLabelIndex >= 0 && m_vLabel[nTargetLabelIndex].Type == nTargetType && uTargetAddress >= m_uAddress && uTargetAddress + uMinSize <= m_uAddress + m_uFileSize)
					{
						if (!m_vLabel[nTargetLabelIndex].Name.empty())
						{
							fprintf(fp, "_%08X: .4byte %s\n", uAddress, m_vLabel[nTargetLabelIndex].Name.c_str());
						}
						else
						{
							fprintf(fp, "_%08X: .4byte %s_%08X\n", uAddress, (m_vLabel[nTargetLabelIndex].BranchType == kBranchTypeBL ? "sub" : ""), uTargetAddress);
						}
						bPrint = true;
					}
				}
				if (!bPrint)
				{
					const n32 nTargetLabelIndex = getLabelIndex(uLong);
					if (nTargetLabelIndex >= 0 && m_vLabel[nTargetLabelIndex].Type != kLabelTypeArmCode && m_vLabel[nTargetLabelIndex].Type != kLabelTypeThumbCode && uLong >= m_uAddress && uLong < m_uAddress + m_uFileSize)
					{
						if (!m_vLabel[nTargetLabelIndex].Name.empty())
						{
							fprintf(fp, "_%08X: .4byte %s\n", uAddress, m_vLabel[nTargetLabelIndex].Name.c_str());
						}
						else
						{
							fprintf(fp, "_%08X: .4byte _%08X\n", uAddress, uLong);
						}
						bPrint = true;
					}
				}
				if (!bPrint)
				{
					fprintf(fp, "_%08X: .4byte 0x%08X\n", uAddress, uLong);
					bPrint = true;
				}
				uAddress += 4;
			}
			break;
		case kLabelTypeJumpTable:
			{
				u32 uEndAddress = uAddress + m_vLabel[nLabelIndex].Size;
				n32 nCaseNum = 0;
				fprintf(fp, "_%08X: @ jump table\n", uAddress);
				while (uAddress < uEndAddress)
				{
					u32 uTargetAddress = 0;
					if (!getLong(uAddress, uTargetAddress))
					{
						bResult = false;
						break;
					}
					// TODO: uncomment begin
					//fprintf(fp, "\t.4byte _%08X @ case %d\n", uTargetAddress, nCaseNum);
					// TODO: uncomment end
					// TODO: delete begin
					if (uTargetAddress >= m_uAddress && uTargetAddress < m_uAddress + m_uFileSize)
					{
						fprintf(fp, "\t.4byte _%08X @ case %d\n", uTargetAddress, nCaseNum);
					}
					else
					{
						fprintf(fp, "\t.4byte 0x%08X @ case %d\n", uTargetAddress, nCaseNum);
					}
					// TODO: delete end
					nCaseNum++;
					uAddress += 4;
				}
			}
			break;
		}
		if (!bResult)
		{
			break;
		}
	}
	if (m_fp != nullptr)
	{
		fclose(m_fp);
		m_fp = nullptr;
	}
	return bResult;
}

bool CDisasm::printGap(u32 a_uAddress, u32 a_uNextAddress) const
{
	if (a_uAddress >= a_uNextAddress)
	{
		UPrintf(USTR("ERROR: address range [0x%08X, 0x%08X) is invalid\n\n"), a_uAddress, a_uNextAddress);
		return false;
	}
	if (a_uAddress < m_uAddress || a_uNextAddress > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: address range [0x%08X, 0x%08X) is out of range [0x%08X, 0x%08X)\n\n"), a_uAddress, a_uNextAddress, m_uAddress, m_uAddress + m_uFileSize);
		return false;
	}
	FILE* fp = m_fp;
	if (fp == nullptr)
	{
		fp = stdout;
	}
	if (a_uAddress % 4 == 2 && a_uNextAddress - a_uAddress >= 2)
	{
		u16 uPadding = 0;
		if (!getShort(a_uAddress, uPadding))
		{
			return false;
		}
		if (uPadding == 0)
		{
			fprintf(fp, "\t.align 2, 0\n");
			a_uAddress += 2;
		}
		else if (uPadding == 0x46C0)
		{
			// mov r8, r8 => nop
			fprintf(fp, "\tnop\n");
			a_uAddress += 2;
		}
		if (a_uAddress == a_uNextAddress)
		{
			return true;
		}
	}
	fprintf(fp, "_%08X:\n", a_uAddress);
	for (u32 i = 0; a_uAddress + i < a_uNextAddress; i++)
	{
		u32 uAddress = a_uAddress + i;
		n32 nPos = uAddress % s_nOptionDataColumnWidth;
		if (i == 0 || nPos == 0)
		{
			fprintf(fp, "\t.byte");
		}
		u8 uByte = 0;
		if (!getByte(uAddress, uByte))
		{
			return false;
		}
		if (nPos == s_nOptionDataColumnWidth - 1 || uAddress == a_uNextAddress - 1)
		{
			fprintf(fp, " 0x%02X\n", uByte);
		}
		else
		{
			fprintf(fp, " 0x%02X,", uByte);
		}
	}
	return true;
}

bool CDisasm::printInsn(const cs_insn* a_pInsn, n32 a_nType) const
{
	if (a_pInsn == nullptr)
	{
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return false;
	}
	if (a_nType != kLabelTypeArmCode && a_nType != kLabelTypeThumbCode)
	{
		UPrintf(USTR("ERROR: type %d is invalid\n\n"), a_nType);
		return false;
	}
	FILE* fp = m_fp;
	if (fp == nullptr)
	{
		fp = stdout;
	}
	if (s_bOptionShowAddrComments)
	{
		fprintf(fp, "\t/*0x%08X*/ %s %s\n", static_cast<u32>(a_pInsn->address), a_pInsn->mnemonic, a_pInsn->op_str);
	}
	else
	{
		if (isBranch(a_pInsn) && a_pInsn->id != ARM_INS_BX)
		{
			u32 uTargetAddress = getBranchTarget(a_pInsn);
			if (uTargetAddress == 0)
			{
				return false;
			}
			else if (uTargetAddress < m_uAddress || uTargetAddress >= m_uAddress + m_uFileSize)
			{
				UPrintf(USTR("ERROR: branch target 0x%08X is out of range [0x%08X, 0x%08X)\n\n"), uTargetAddress, m_uAddress, m_uAddress + m_uFileSize);
				return false;
			}
			const n32 nTargetLabelIndex = getLabelIndex(uTargetAddress);
			if (nTargetLabelIndex < 0)
			{
				UPrintf(USTR("ERROR: label at 0x%08X not found\n\n"), uTargetAddress);
				return false;
			}
			if (!m_vLabel[nTargetLabelIndex].Name.empty())
			{
				fprintf(fp, "\t%s %s\n", a_pInsn->mnemonic, m_vLabel[nTargetLabelIndex].Name.c_str());
			}
			else
			{
				fprintf(fp, "\t%s %s_%08X\n", a_pInsn->mnemonic, (m_vLabel[nTargetLabelIndex].BranchType == kBranchTypeBL ? "sub" : ""), uTargetAddress);
			}
		}
		else
		{
			const cs_arm* pArm = &a_pInsn->detail->arm;
			bool bPrint = false;
			if (isPoolLoad(a_pInsn))
			{
				const cs_arm_op* pArmOp0 = &pArm->operands[0];
				u32 uPoolAddress = getPoolLoad(a_pInsn, a_nType);
				if (uPoolAddress == 0)
				{
					return false;
				}
				u32 uAddressX = 0;
				if (!getLong(uPoolAddress, uAddressX))
				{
					return false;
				}
				if (!bPrint && uAddressX % 4 != 2)
				{
					u32 uAddress = uAddressX & ~0x1;
					n32 nType = uAddressX % 4 == 0 ? kLabelTypeArmCode : kLabelTypeThumbCode;
					u32 uMinSize = getMinSize(nType);
					const n32 nLabelIndex = getLabelIndex(uAddress);
					if (nLabelIndex >= 0 && m_vLabel[nLabelIndex].Type == nType && uAddress >= m_uAddress && uAddress + uMinSize <= m_uAddress + m_uFileSize)
					{
						if (!m_vLabel[nLabelIndex].Name.empty())
						{
							fprintf(fp, "\t%s %s, _%08X @ =%s\n", a_pInsn->mnemonic, cs_reg_name(m_uHandle, pArmOp0->reg), uPoolAddress, m_vLabel[nLabelIndex].Name.c_str());
						}
						else
						{
							fprintf(fp, "\t%s %s, _%08X @ =%s_%08X\n", a_pInsn->mnemonic, cs_reg_name(m_uHandle, pArmOp0->reg), uPoolAddress, (m_vLabel[nLabelIndex].BranchType == kBranchTypeBL ? "sub" : ""), uAddress);
						}
						bPrint = true;
					}
				}
				if (!bPrint)
				{
					const n32 nLabelIndex = getLabelIndex(uAddressX);
					if (nLabelIndex >= 0 && m_vLabel[nLabelIndex].Type != kLabelTypeArmCode && m_vLabel[nLabelIndex].Type != kLabelTypeThumbCode && uAddressX >= m_uAddress && uAddressX < m_uAddress + m_uFileSize)
					{
						if (!m_vLabel[nLabelIndex].Name.empty())
						{
							fprintf(fp, "\t%s %s, _%08X @ =%s\n", a_pInsn->mnemonic, cs_reg_name(m_uHandle, pArmOp0->reg), uPoolAddress, m_vLabel[nLabelIndex].Name.c_str());
						}
						else
						{
							fprintf(fp, "\t%s %s, _%08X @ =_%08X\n", a_pInsn->mnemonic, cs_reg_name(m_uHandle, pArmOp0->reg), uPoolAddress, uAddressX);
						}
						bPrint = true;
					}
				}
				if (!bPrint)
				{
					fprintf(fp, "\t%s %s, _%08X @ =0x%08X\n", a_pInsn->mnemonic, cs_reg_name(m_uHandle, pArmOp0->reg), uPoolAddress, uAddressX);
					bPrint = true;
				}
			}
			else
			{
				if (!bPrint && a_pInsn->id == ARM_INS_ADD && pArm->op_count == 3)
				{
					// add rd, sp, rd => add rd, sp
					const cs_arm_op* pArmOp0 = &pArm->operands[0];
					const cs_arm_op* pArmOp1 = &pArm->operands[1];
					const cs_arm_op* pArmOp2 = &pArm->operands[2];
					if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_REG && pArmOp2->type == ARM_OP_REG && pArmOp1->reg == ARM_REG_SP && pArmOp0->reg == pArmOp2->reg)
					{
						fprintf(fp, "\t%s %s, %s\n", a_pInsn->mnemonic, cs_reg_name(m_uHandle, pArmOp0->reg), cs_reg_name(m_uHandle, pArmOp1->reg));
						bPrint = true;
					}
				}
				if (!bPrint && a_nType == kLabelTypeArmCode && a_pInsn->id == ARM_INS_ADD && pArm->op_count == 3)
				{
					const cs_arm_op* pArmOp0 = &pArm->operands[0];
					const cs_arm_op* pArmOp1 = &pArm->operands[1];
					const cs_arm_op* pArmOp2 = &pArm->operands[2];
					if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_REG && pArmOp2->type == ARM_OP_IMM && pArmOp1->reg == ARM_REG_PC)
					{
						u32 uAddressX = static_cast<u32>((a_pInsn->address & ~0x3uLL) + pArmOp2->imm + 8);
						if (!bPrint && uAddressX % 4 != 2)
						{
							u32 uAddress = uAddressX & ~0x1;
							n32 nType = uAddressX % 4 == 0 ? kLabelTypeArmCode : kLabelTypeThumbCode;
							u32 uMinSize = getMinSize(nType);
							const n32 nLabelIndex = getLabelIndex(uAddress);
							if (nLabelIndex >= 0 && m_vLabel[nLabelIndex].Type == nType && uAddress >= m_uAddress && uAddress + uMinSize <= m_uAddress + m_uFileSize)
							{
								if (!m_vLabel[nLabelIndex].Name.empty())
								{
									fprintf(fp, "\tadd %s, pc, #0x%X @ =%s\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp2->imm, m_vLabel[nLabelIndex].Name.c_str());
								}
								else
								{
									fprintf(fp, "\tadd %s, pc, #0x%X @ =%s_%08X\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp2->imm, (m_vLabel[nLabelIndex].BranchType == kBranchTypeBL ? "sub" : ""), uAddress);
								}
								bPrint = true;
							}
						}
						if (!bPrint)
						{
							const n32 nLabelIndex = getLabelIndex(uAddressX);
							if (nLabelIndex >= 0 && m_vLabel[nLabelIndex].Type != kLabelTypeArmCode && m_vLabel[nLabelIndex].Type != kLabelTypeThumbCode && uAddressX >= m_uAddress && uAddressX < m_uAddress + m_uFileSize)
							{
								if (!m_vLabel[nLabelIndex].Name.empty())
								{
									fprintf(fp, "\tadd %s, pc, #0x%X @ =%s\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp2->imm, m_vLabel[nLabelIndex].Name.c_str());
								}
								else
								{
									fprintf(fp, "\tadd %s, pc, #0x%X @ =_%08X\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp2->imm, uAddressX);
								}
								bPrint = true;
							}
						}
						if (!bPrint)
						{
							fprintf(fp, "\tadd %s, pc, #0x%X @ =0x%08X\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp2->imm, uAddressX);
							bPrint = true;
						}
					}
				}
				if (!bPrint && a_nType == kLabelTypeThumbCode && a_pInsn->id == ARM_INS_ADR && pArm->op_count == 2)
				{
					// adr rd, #imm => add rd, pc, #imm
					const cs_arm_op* pArmOp0 = &pArm->operands[0];
					const cs_arm_op* pArmOp1 = &pArm->operands[1];
					if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_IMM)
					{
						u32 uAddress = static_cast<u32>((a_pInsn->address & ~0x3uLL) + pArmOp1->imm + 4);
						const n32 nLabelIndex = getLabelIndex(uAddress);
						if (nLabelIndex >= 0 && m_vLabel[nLabelIndex].Type != kLabelTypeThumbCode)
						{
							if (!m_vLabel[nLabelIndex].Name.empty())
							{
								fprintf(fp, "\tadd %s, pc, #0x%X @ =%s\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp1->imm, m_vLabel[nLabelIndex].Name.c_str());
							}
							else
							{
								fprintf(fp, "\tadd %s, pc, #0x%X @ =%s_%08X\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp1->imm, (m_vLabel[nLabelIndex].BranchType == kBranchTypeBL ? "sub" : ""), uAddress);
							}
						}
						else
						{
							fprintf(fp, "\tadd %s, pc, #0x%X @ =0x%08X\n", cs_reg_name(m_uHandle, pArmOp0->reg), pArmOp1->imm, uAddress);
						}
						bPrint = true;
					}
				}
				if (!bPrint)
				{
					fprintf(fp, "\t%s %s\n", a_pInsn->mnemonic, a_pInsn->op_str);
					bPrint = true;
				}
			}
		}
	}
	return true;
}

n32 CDisasm::addLabel(u32 a_uAddress, n32 a_nType, const string& a_sName)
{
	if (a_nType != kLabelTypeArmCode && a_nType != kLabelTypeThumbCode && a_nType != kLabelTypeData && a_nType != kLabelTypePool && a_nType != kLabelTypeJumpTable)
	{
		UPrintf(USTR("ERROR: label type %d is invalid\n\n"), a_nType);
		return -1;
	}
	u32 uMinSize = getMinSize(a_nType);
	if (a_uAddress < m_uAddress || a_uAddress + uMinSize > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: address 0x%08X is out of range [0x%08X, 0x%08X]\n\n"), a_uAddress, m_uAddress, m_uAddress + m_uFileSize - uMinSize);
		return -1;
	}
	u32 uAlignment = getAlignment(a_nType);
	if (a_uAddress % uAlignment != 0)
	{
		UPrintf(USTR("ERROR: address 0x%08X is not aligned\n\n"), a_uAddress);
		return -1;
	}
	if (m_bVerbose)
	{
		fprintf(stderr, "adding label 0x%08X\n", a_uAddress);
	}
	map<u32, n32>::const_iterator it = m_mLabelAddressIndex.find(a_uAddress);
	if (it != m_mLabelAddressIndex.end())
	{
		const n32 nLabelIndex = it->second;
		m_vLabel[nLabelIndex].Type = a_nType;
		if (!a_sName.empty())
		{
			m_vLabel[nLabelIndex].Name = a_sName;
		}
		return nLabelIndex;
	}
	const n32 nLabelIndex = static_cast<n32>(m_vLabel.size());
	SLabel label;
	label.Address = a_uAddress;
	label.Type = a_nType;
	if (a_nType == kLabelTypeArmCode || a_nType == kLabelTypeThumbCode)
	{
		label.BranchType = kBranchTypeBL;
	}
	label.Name = a_sName;
	m_vLabel.push_back(label);
	m_sUnprocessedLabelAddress.insert(a_uAddress);
	m_mLabelAddressIndex[a_uAddress] = nLabelIndex;
	return nLabelIndex;
}

bool CDisasm::addLabelByJumpTable(u32 a_uAddress, u32 a_uCount, n32 a_nLabelType)
{
	if (a_uAddress % 4 != 0)
	{
		UPrintf(USTR("ERROR: address 0x%08X is not aligned\n\n"), a_uAddress);
		return false;
	}
	if (a_uCount < 1)
	{
		UPrintf(USTR("ERROR: count %u is invalid\n\n"), a_uCount);
		return false;
	}
	if (a_nLabelType != kLabelTypeUnknown && a_nLabelType != kLabelTypeArmCode && a_nLabelType != kLabelTypeThumbCode)
	{
		UPrintf(USTR("ERROR: label type %d is invalid\n\n"), a_nLabelType);
		return false;
	}
	u32 uEndAddress = a_uAddress + a_uCount * 4;
	if (a_uAddress < m_uAddress || uEndAddress > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: address range [0x%08X, 0x%08X) is out of range [0x%08X, 0x%08X)\n\n"), a_uAddress, uEndAddress, m_uAddress, m_uAddress + m_uFileSize);
		return false;
	}
	vector<u32> vTargetAddress(a_uCount);
	bool bThumb = false;
	for (u32 i = 0; i < a_uCount; i++)
	{
		u32 uAddress = a_uAddress + i * 4;
		u32& uTargetAddress = vTargetAddress[i];
		if (!getLong(uAddress, uTargetAddress))
		{
			return false;
		}
		switch (uTargetAddress % 4)
		{
		case 0:
			break;
		case 2:
			bThumb = true;
			break;
		default:
			UPrintf(USTR("ERROR: target address 0x%08X is not aligned\n\n"), uTargetAddress);
			return false;
		}
		if (uTargetAddress >= a_uAddress && uTargetAddress < uEndAddress)
		{
			UPrintf(USTR("ERROR: target address 0x%08X is in range [0x%08X, 0x%08X)\n\n"), uTargetAddress, a_uAddress, uEndAddress);
			return false;
		}
	}
	if (bThumb)
	{
		if (a_nLabelType == kLabelTypeArmCode)
		{
			UPrintf(USTR("ERROR: label type 'arm' is conflict with thumb target address\n\n"));
			return false;
		}
		a_nLabelType = kLabelTypeThumbCode;
	}
	else
	{
		if (a_nLabelType == kLabelTypeUnknown)
		{
			UPrintf(USTR("ERROR: require label type\n\n"));
			return false;
		}
	}
	for (u32 i = 0; i < a_uCount; i++)
	{
		u32& uTargetAddress = vTargetAddress[i];
		const n32 nLabelIndex = addLabel(uTargetAddress, a_nLabelType, "");
		if (nLabelIndex < 0)
		{
			return false;
		}
		m_vLabel[nLabelIndex].BranchType = kBranchTypeB;
	}
	return true;
}

n32 CDisasm::addCodeLabel(u32 a_uAddressX)
{
	if (a_uAddressX % 4 == 2)
	{
		UPrintf(USTR("ERROR: address 0x%08X is invalid\n\n"), a_uAddressX);
		return -1;
	}
	u32 uAddress = a_uAddressX & ~0x1;
	n32 nType = a_uAddressX % 4 == 0 ? kLabelTypeArmCode : kLabelTypeThumbCode;
	u32 uMinSize = getMinSize(nType);
	if (uAddress < m_uAddress || uAddress + uMinSize > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: address range [0x%08X, 0x%08X) is out of range [0x%08X, 0x%08X)\n\n"), uAddress, uAddress + uMinSize, m_uAddress, m_uAddress + m_uFileSize);
		return -1;
	}
	const n32 nLabelIndex = addLabel(uAddress, nType, "");
	if (nLabelIndex < 0)
	{
		return -1;
	}
	m_vLabel[nLabelIndex].BranchType = kBranchTypeBL;
	m_vLabel[nLabelIndex].IsProcessed = false;
	m_vLabel[nLabelIndex].IsFunc = true;
	m_sUnprocessedLabelAddress.insert(uAddress);
	// TODO: delete begin
	if (m_vLabel[nLabelIndex].Inactive)
	{
		m_sUnprocessedLabelAddress.erase(m_vLabel[nLabelIndex].Address);
	}
	// TODO: delete end
	return nLabelIndex;
}

n32 CDisasm::getUnprocessedLabelIndex() const
{
	set<u32>::const_iterator itAddress = m_sUnprocessedLabelAddress.begin();
	if (itAddress != m_sUnprocessedLabelAddress.end())
	{
		u32 uAddress = *itAddress;
		map<u32, n32>::const_iterator it = m_mLabelAddressIndex.find(uAddress);
		if (it != m_mLabelAddressIndex.end())
		{
			n32 nLabelIndex = it->second;
			return nLabelIndex;
		}
	}
	return -1;
}

n32 CDisasm::getNextLabelIndex(u32 a_uAddress) const
{
	// TODO: delete begin
	for (map<u32, n32>::const_iterator it = m_mLabelAddressIndex.upper_bound(a_uAddress); it != m_mLabelAddressIndex.end(); ++it)
	{
		n32 nLabelIndex = it->second;
		if (!m_vLabel[nLabelIndex].Inactive)
		{
			return nLabelIndex;
		}
	}
	// TODO: delete end
	// TODO: uncomment begin
	map<u32, n32>::const_iterator it = m_mLabelAddressIndex.upper_bound(a_uAddress);
	if (it != m_mLabelAddressIndex.end())
	{
		n32 nLabelIndex = it->second;
		return nLabelIndex;
	}
	// TODO: uncomment end
	return -1;
}

bool CDisasm::armJumpTableStateMachine(const cs_insn* a_pInsn)
{
	static u32 c_uReg = ARM_REG_INVALID;
	static u32 c_uCount = 0;
	static u32 c_uJumpTableBegin = 0;
	if (a_pInsn == nullptr)
	{
		m_nArmJumpTableState = 0;
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return false;
	}
	const cs_arm* pArm = &a_pInsn->detail->arm;
	bool bMatch = false;
	switch (m_nArmJumpTableState)
	{
	case 0:
		// cmp rA, #imm
		if (a_pInsn->id == ARM_INS_CMP && pArm->cc == ARM_CC_AL && pArm->op_count == 2)
		{
			const cs_arm_op* pArmOp0 = &pArm->operands[0];
			const cs_arm_op* pArmOp1 = &pArm->operands[1];
			if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_IMM)
			{
				c_uReg = pArmOp0->reg;
				c_uCount = pArmOp1->imm + 1;
				bMatch = true;
			}
		}
		break;
	case 1:
		// ldrls pc, [pc, rA, lsl #2]
		if (a_pInsn->id == ARM_INS_LDR && pArm->cc == ARM_CC_LS && pArm->op_count == 2)
		{
			const cs_arm_op* pArmOp0 = &pArm->operands[0];
			const cs_arm_op* pArmOp1 = &pArm->operands[1];
			if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_MEM && pArmOp0->reg == ARM_REG_PC && pArmOp1->shift.type == ARM_SFT_LSL && pArmOp1->shift.value == 2)
			{
				const arm_op_mem* pArmOp1Mem = &pArmOp1->mem;
				if (pArmOp1Mem->base == ARM_REG_PC && pArmOp1Mem->index == c_uReg && pArmOp1Mem->scale == 1)
				{
					c_uJumpTableBegin = static_cast<u32>(a_pInsn->address + 8);
					bMatch = true;
				}
			}
		}
		break;
	}
	if (!bMatch)
	{
		m_nArmJumpTableState = 0;
		return true;
	}
	if (m_nArmJumpTableState == 1)
	{
		m_nArmJumpTableState = 0;
		const n32 nLabelIndex0 = addLabel(c_uJumpTableBegin, kLabelTypeJumpTable, "");
		if (nLabelIndex0 < 0)
		{
			return false;
		}
		for (u32 i = 0; i < c_uCount; i++)
		{
			u32 uAddress = c_uJumpTableBegin + i * 4;
			// TODO: delete begin
			const n32 nPoolLabelIndex = addLabel(uAddress, kLabelTypePool, "");
			if (nPoolLabelIndex < 0)
			{
				return false;
			}
			// TODO: delete end
			u32 uTargetAddress = 0;
			if (!getLong(uAddress, uTargetAddress))
			{
				return false;
			}
			const n32 nLabelIndex1 = addLabel(uTargetAddress, kLabelTypeArmCode, "");
			if (nLabelIndex1 < 0)
			{
				return false;
			}
			m_vLabel[nLabelIndex1].BranchType = kBranchTypeB;
			// TODO: delete begin
			m_vLabel[nLabelIndex1].IsFarJump = true;
			// TODO: delete end
		}
	}
	else
	{
		m_nArmJumpTableState++;
	}
	return true;
}

bool CDisasm::thumbJumpTableStateMachine(const cs_insn* a_pInsn)
{
	static u32 c_uRegM = ARM_REG_INVALID;
	static u32 c_uRegN = ARM_REG_INVALID;
	static u32 c_uJumpTableBegin = 0;
	// TODO: uncomment begin
	//static bool c_bGracePeriod = false;
	// TODO: uncomment end
	if (a_pInsn == nullptr)
	{
		m_nThumbJumpTableState = 0;
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return false;
	}
	const cs_arm* pArm = &a_pInsn->detail->arm;
	bool bMatch = false;
	switch (m_nThumbJumpTableState)
	{
	case 0:
		// lsl rA, rB, #2
		if (a_pInsn->id == ARM_INS_LSL && pArm->op_count == 3)
		{
			const cs_arm_op* pArmOp0 = &pArm->operands[0];
			const cs_arm_op* pArmOp1 = &pArm->operands[1];
			const cs_arm_op* pArmOp2 = &pArm->operands[2];
			if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_REG && pArmOp2->type == ARM_OP_IMM && pArmOp2->imm == 2)
			{
				c_uRegM = pArmOp0->reg;
				// TODO: uncomment begin
				//c_bGracePeriod = false;
				// TODO: uncomment end
				bMatch = true;
			}
		}
		break;
	case 1:
		// ldr rC, [pc, #imm]
		if (isPoolLoad(a_pInsn))
		{
			const cs_arm_op* pArmOp0 = &pArm->operands[0];
			if (pArmOp0->type == ARM_OP_REG)
			{
				c_uRegN = pArmOp0->reg;
				if (c_uRegN != c_uRegM)
				{
					u32 uPoolAddress = getPoolLoad(a_pInsn, kLabelTypeThumbCode);
					if (uPoolAddress == 0)
					{
						return false;
					}
					if (!getLong(uPoolAddress, c_uJumpTableBegin))
					{
						return false;
					}
					if (c_uJumpTableBegin >= m_uAddress && c_uJumpTableBegin + 4 <= m_uAddress + m_uFileSize)
					{
						bMatch = true;
					}
				}
			}
		}
		break;
	case 2:
		// add rD, rA, rC
		// add rD, rC, rA
		if (a_pInsn->id == ARM_INS_ADD && pArm->op_count == 3)
		{
			const cs_arm_op* pArmOp0 = &pArm->operands[0];
			const cs_arm_op* pArmOp1 = &pArm->operands[1];
			const cs_arm_op* pArmOp2 = &pArm->operands[2];
			if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_REG && pArmOp2->type == ARM_OP_REG && ((pArmOp1->reg == c_uRegM && pArmOp2->reg == c_uRegN) || (pArmOp1->reg == c_uRegN && pArmOp2->reg == c_uRegM)))
			{
				c_uRegM = pArmOp0->reg;
				bMatch = true;
			}
		}
		break;
	case 3:
		// ldr rE, [rD]
		if (a_pInsn->id == ARM_INS_LDR && pArm->op_count == 2)
		{
			const cs_arm_op* pArmOp0 = &pArm->operands[0];
			const cs_arm_op* pArmOp1 = &pArm->operands[1];
			if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_MEM)
			{
				const arm_op_mem* pArmOp1Mem = &pArmOp1->mem;
				if (pArmOp1Mem->index == ARM_REG_INVALID)
				{
					c_uRegN = pArmOp1Mem->base;
					if (c_uRegN == c_uRegM)
					{
						c_uRegM = pArmOp0->reg;
						bMatch = true;
					}
				}
			}
		}
		break;
	case 4:
		// mov pc, rE
		if (a_pInsn->id == ARM_INS_MOV && pArm->op_count == 2)
		{
			const cs_arm_op* pArmOp0 = &pArm->operands[0];
			const cs_arm_op* pArmOp1 = &pArm->operands[1];
			if (pArmOp0->type == ARM_OP_REG && pArmOp1->type == ARM_OP_REG && pArmOp0->reg == ARM_REG_PC && pArmOp1->reg != ARM_REG_LR && pArmOp1->reg == c_uRegM)
			{
				bMatch = true;
			}
		}
		break;
	}
	if (!bMatch)
	{
		// TODO: uncomment begin
		//if (!c_bGracePeriod)
		//{
		//	c_bGracePeriod = true;
		//}
		//else
		//{
		//	m_nThumbJumpTableState = 0;
		//}
		// TODO: uncomment end
		// TODO: delete begin
		m_nThumbJumpTableState = 0;
		// TODO: delete end
		return true;
	}
	if (m_nThumbJumpTableState == 4)
	{
		m_nThumbJumpTableState = 0;
		const n32 nLabelIndex0 = addLabel(c_uJumpTableBegin, kLabelTypeJumpTable, "");
		if (nLabelIndex0 < 0)
		{
			return false;
		}
		u32 uFirstTargetAddress = UINT32_MAX;
		u32 uAddress = c_uJumpTableBegin;
		while (uAddress < uFirstTargetAddress)
		{
			u32 uTargetAddress = 0;
			if (!getLong(uAddress, uTargetAddress))
			{
				return false;
			}
			if (uTargetAddress < m_uAddress || uTargetAddress + 2 > m_uAddress + m_uFileSize)
			{
				break;
			}
			if (uTargetAddress > c_uJumpTableBegin && uTargetAddress < uFirstTargetAddress)
			{
				uFirstTargetAddress = uTargetAddress;
			}
			const n32 nLabelIndex1 = addLabel(uTargetAddress, kLabelTypeThumbCode, "");
			if (nLabelIndex1 < 0)
			{
				return false;
			}
			m_vLabel[nLabelIndex1].BranchType = kBranchTypeB;
			// TODO: delete begin
			m_vLabel[nLabelIndex1].IsFarJump = true;
			// TODO: delete end
			uAddress += 4;
		}
	}
	else
	{
		m_nThumbJumpTableState++;
	}
	return true;
}

u32 CDisasm::getBranchTarget(const cs_insn* a_pInsn) const
{
	if (a_pInsn == nullptr)
	{
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return 0;
	}
	if (!isBranch(a_pInsn))
	{
		UPrintf(USTR("ERROR: instruction is not a branch /*0x%08X*/ %") PRIUS USTR(" %") PRIUS USTR("\n\n"), static_cast<u32>(a_pInsn->address), AToU(a_pInsn->mnemonic).c_str(), AToU(a_pInsn->op_str).c_str());
		return 0;
	}
	const cs_arm* pArm = &a_pInsn->detail->arm;
	if (pArm->op_count != 1)
	{
		UPrintf(USTR("ERROR: instruction has no operand /*0x%08X*/ %") PRIUS USTR(" %") PRIUS USTR("\n\n"), static_cast<u32>(a_pInsn->address), AToU(a_pInsn->mnemonic).c_str(), AToU(a_pInsn->op_str).c_str());
		return 0;
	}
	const cs_arm_op* pArmOp0 = &pArm->operands[0];
	if (pArmOp0->type == ARM_OP_IMM)
	{
		return pArmOp0->imm;
	}
	return 0;
}

u32 CDisasm::getPoolLoad(const cs_insn* a_pInsn, n32 a_nMode) const
{
	if (a_pInsn == nullptr)
	{
		UPrintf(USTR("ERROR: instruction is invalid\n\n"));
		return 0;
	}
	if (!isPoolLoad(a_pInsn))
	{
		UPrintf(USTR("ERROR: instruction is not a pool load\n\n"));
		return 0;
	}
	const cs_arm* pArm = &a_pInsn->detail->arm;
	const cs_arm_op* pArmOp1 = &pArm->operands[1];
	const arm_op_mem* pArmOp1Mem = &pArmOp1->mem;
	u32 uPoolAddress = static_cast<u32>((a_pInsn->address & ~0x3uLL) + pArmOp1Mem->disp + (a_nMode == kLabelTypeArmCode ? 8 : 4));
	if (uPoolAddress < m_uAddress || uPoolAddress + 4 > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: pool address 0x%08X is out of range [0x%08X, 0x%08X]\n\n"), uPoolAddress, m_uAddress, m_uAddress + m_uFileSize - 4);
		return 0;
	}
	return uPoolAddress;
}

bool CDisasm::getByte(u32 a_uAddress, u8& a_uValue) const
{
	if (a_uAddress < m_uAddress || a_uAddress + 1 > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: address 0x%08X is out of range [0x%08X, 0x%08X]\n\n"), a_uAddress, m_uAddress, m_uAddress + m_uFileSize - 1);
		return false;
	}
	u32 uFileOffset = a_uAddress - m_uAddress;
	a_uValue = m_vFile[uFileOffset];
	return true;
}

bool CDisasm::getShort(u32 a_uAddress, u16& a_uValue) const
{
	if (a_uAddress < m_uAddress || a_uAddress + 2 > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: address 0x%08X is out of range [0x%08X, 0x%08X]\n\n"), a_uAddress, m_uAddress, m_uAddress + m_uFileSize - 2);
		return false;
	}
	u32 uFileOffset = a_uAddress - m_uAddress;
	a_uValue = *reinterpret_cast<const u16*>(&*m_vFile.begin() + uFileOffset);
	return true;
}

bool CDisasm::getLong(u32 a_uAddress, u32& a_uValue) const
{
	if (a_uAddress < m_uAddress || a_uAddress + 4 > m_uAddress + m_uFileSize)
	{
		UPrintf(USTR("ERROR: address 0x%08X is out of range [0x%08X, 0x%08X]\n\n"), a_uAddress, m_uAddress, m_uAddress + m_uFileSize - 4);
		return false;
	}
	u32 uFileOffset = a_uAddress - m_uAddress;
	a_uValue = *reinterpret_cast<const u32*>(&*m_vFile.begin() + uFileOffset);
	return true;
}

n32 CDisasm::getLabelIndex(u32 a_uAddress) const
{
	map<u32, n32>::const_iterator it = m_mLabelAddressIndex.find(a_uAddress);
	if (it != m_mLabelAddressIndex.end())
	{
		n32 nLabelIndex = it->second;
		// TODO: uncomment begin
		//return nLabelIndex;
		// TODO: uncomment end
		// TODO: delete begin
		if (!m_vLabel[nLabelIndex].Inactive)
		{
			return nLabelIndex;
		}
		// TODO: delete end
	}
	return -1;
}
