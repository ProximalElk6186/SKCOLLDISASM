typedef unsigned char   undefined;

typedef unsigned int    word;
typedef unsigned char    byte;
typedef struct OLD_IMAGE_DOS_HEADER OLD_IMAGE_DOS_HEADER, *POLD_IMAGE_DOS_HEADER;

struct OLD_IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
};




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x00010400) overlaps instruction at (ram,0x000103ff)
// 
// WARNING: Stack frame is not setup normally: Input value of stackpointer is not used
// WARNING: This function may have set the stack pointer
// WARNING: Removing unreachable block (ram,0x0001009c)
// WARNING: Type propagation algorithm not settling

void entry(void)

{
  char **ppcVar1;
  byte *pbVar2;
  uint *puVar3;
  char *pcVar4;
  char *pcVar5;
  undefined2 *puVar7;
  code **ppcVar8;
  code *pcVar9;
  code *pcVar10;
  byte bVar11;
  char cVar12;
  byte bVar13;
  char cVar14;
  byte bVar15;
  char cVar19;
  int iVar16;
  uint uVar17;
  undefined uVar20;
  char *pcVar18;
  int in_CX;
  int iVar21;
  undefined2 uVar22;
  int *in_BX;
  undefined *puVar23;
  undefined *puVar24;
  undefined2 *puVar25;
  undefined *puVar26;
  undefined *puVar27;
  undefined2 *puVar28;
  undefined2 *puVar29;
  undefined *puVar30;
  int unaff_BP;
  undefined *puVar31;
  undefined *puVar32;
  undefined2 *unaff_SI;
  uint *puVar33;
  uint *puVar34;
  undefined2 *unaff_DI;
  code **ppcVar35;
  undefined2 unaff_ES;
  bool bVar36;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  undefined4 uVar37;
  char *pcVar6;
  
                    // WARNING: Read-only address (ram,0x000100b6) is written
  uRam000100b6 = 0x1000;
  puVar23 = (undefined *)0xb8;
  pcVar10 = (code *)swi(0x21);
  (*pcVar10)();
  pcVar10 = (code *)swi(0x21);
  uVar37 = (*pcVar10)();
  iVar21 = (int)((ulong)uVar37 >> 0x10);
  iVar16 = (int)uVar37;
  *(undefined **)(puVar23 + -2) = puVar23;
  puVar24 = puVar23 + -4;
  *(undefined2 *)(puVar23 + -4) = 0x7369;
  pbVar2 = (byte *)((int)in_BX + (int)unaff_SI + 0x72);
  bVar13 = (byte)((ulong)uVar37 >> 0x18);
  *pbVar2 = *pbVar2 & bVar13;
  out(*unaff_SI,iVar21);
  cVar14 = (char)in_CX;
  ppcVar35 = (code **)(unaff_DI + 1);
  uVar22 = in(iVar21);
  *unaff_DI = uVar22;
  pbVar2 = (byte *)((int)ppcVar35 + unaff_BP + 0x61);
  bVar11 = (byte)((ulong)uVar37 >> 8);
  *pbVar2 = *pbVar2 & bVar11;
  out(*(undefined *)(unaff_SI + 1),iVar21);
  out(*(undefined *)((int)unaff_SI + 3),iVar21);
  puVar29 = unaff_SI + 3;
  out(unaff_SI[2],iVar21);
  if (*pbVar2 != 0) {
    puVar7 = puVar29;
    puVar29 = (undefined2 *)((int)unaff_SI + 7);
    out(*(undefined *)puVar7,iVar21);
    pbVar2 = (byte *)((int)in_BX + (int)ppcVar35 + 0x6e);
    bVar15 = (byte)((uint)in_CX >> 8);
    *pbVar2 = *pbVar2 & bVar15;
    *(byte *)(unaff_SI + 0x2b) = *(byte *)(unaff_SI + 0x2b) & (byte)uVar37;
    *(int **)(puVar23 + -6) = in_BX;
    *(byte *)((int)unaff_DI + 0x71) = *(byte *)((int)unaff_DI + 0x71) & bVar15;
    iVar16 = (uint)(bVar11 | 10) << 8;
    *(undefined *)((int)in_BX + (int)puVar29) = *(undefined *)((int)in_BX + (int)puVar29);
    *(undefined *)((int)in_BX + (int)puVar29) = *(undefined *)((int)in_BX + (int)puVar29);
    *(undefined *)((int)in_BX + (int)puVar29) = *(undefined *)((int)in_BX + (int)puVar29);
    puVar24 = puVar23 + -8;
    *(int *)(puVar23 + -8) = iVar16;
    unaff_BP = unaff_BP + 1;
  }
  *(char *)((int)in_BX + (int)puVar29) = *(char *)((int)in_BX + (int)puVar29) + (char)iVar16;
  puVar25 = (undefined2 *)(puVar24 + -1);
  *in_BX = *in_BX + iVar16;
  *(char *)(in_BX + -5) = *(char *)(in_BX + -5) + cVar14;
  puVar33 = puVar29 + 1;
  cVar19 = (char)((uint)*puVar29 >> 8);
  bVar11 = (byte)*puVar29 ^ *(byte *)((int)in_BX + (int)puVar33);
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  cVar12 = bVar11 + cVar19;
  *(char *)(unaff_BP + (int)puVar33) = *(char *)(unaff_BP + (int)puVar33) + cVar14;
  *(int *)(unaff_BP + (int)ppcVar35) = *(int *)(unaff_BP + (int)ppcVar35) + in_CX;
  puVar3 = puVar33;
  bVar36 = CARRY2(*puVar3,CONCAT11(cVar19,cVar12));
  *puVar3 = *puVar3 + CONCAT11(cVar19,cVar12);
  bVar11 = cVar12 + bVar36;
  if ((SCARRY1(cVar12,'\0') != SCARRY1(cVar12,bVar36)) == (char)bVar11 < '\0') {
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    cVar12 = *(char *)puVar33;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    ((char *)((int)in_BX + (int)puVar33))[-0xb] =
         ((char *)((int)in_BX + (int)puVar33))[-0xb] + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    iVar21 = CONCAT11(bVar13,(char)((ulong)uVar37 >> 0x10) + cVar12) + 1;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + (char)iVar21;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)(unaff_BP + (int)puVar33) = *(char *)(unaff_BP + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    bVar11 = bVar11 + (char)iVar21;
    puVar25 = (undefined2 *)(puVar24 + -3);
    *(uint **)(puVar24 + -3) = puVar33;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)(unaff_BP + (int)puVar33) = *(char *)(unaff_BP + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  }
  bVar15 = (byte)iVar21;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar15;
  pbVar2 = (byte *)((int)in_BX + (int)puVar33);
  bVar13 = *pbVar2;
  *pbVar2 = *pbVar2 + bVar11;
  *(char *)((int)in_BX + (int)puVar33) =
       *(char *)((int)in_BX + (int)puVar33) + bVar11 + CARRY1(bVar13,bVar11);
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar15;
  pbVar2 = (byte *)((int)in_BX + (int)puVar33);
  bVar13 = *pbVar2;
  *pbVar2 = *pbVar2 + bVar11;
  *(char *)((int)in_BX + (int)puVar33) =
       *(char *)((int)in_BX + (int)puVar33) + bVar11 + CARRY1(bVar13,bVar11);
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar15;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  puVar31 = (undefined *)(unaff_BP + 1);
  *(char *)puVar33 = *(char *)puVar33 + cVar14;
  pcVar4 = (char *)((int)in_BX + (int)puVar33);
  *pcVar4 = *pcVar4 + bVar11;
  in_CX = in_CX + -1;
  if (in_CX == 0 || *pcVar4 == '\0') {
    ((char *)((int)in_BX + (int)puVar33))[0x30] =
         ((char *)((int)in_BX + (int)puVar33))[0x30] + (char)((uint)iVar21 >> 8);
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    pbVar2 = (byte *)((int)in_BX + (int)ppcVar35);
    *pbVar2 = *pbVar2 & bVar15;
    puVar26 = (undefined *)((int)puVar25 + -2);
    *(uint *)((int)puVar25 + -2) =
         (uint)(in_NT & 1) * 0x4000 | (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
         (uint)((char)*pbVar2 < '\0') * 0x80 | (uint)(*pbVar2 == 0) * 0x40 |
         (uint)(in_AF & 1) * 0x10 | (uint)((POPCOUNT(*pbVar2) & 1U) == 0) * 4;
    *ppcVar35 = *ppcVar35;
    ((char *)((int)in_BX + (int)puVar33))[0x42] =
         ((char *)((int)in_BX + (int)puVar33))[0x42] + bVar15;
    puVar27 = (undefined *)((int)puVar25 + -4);
    puVar25 = (undefined2 *)((int)puVar25 + -4);
    *(undefined **)puVar27 = puVar26;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)puVar29 + 0x4595) = *(char *)((int)puVar29 + 0x4595) + bVar11;
  }
  bVar11 = bVar11 + (char)((uint)in_BX >> 8) + *(char *)((int)in_BX + (int)puVar33);
  uVar17 = CONCAT11(cVar19,bVar11);
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
  cVar14 = (char)((uint)in_CX >> 8);
  cRam00006574 = cRam00006574 + cVar14;
  if (cRam00006574 < '\0') {
    puVar29 = (undefined2 *)(*(int *)((int)puVar29 + 99) * 0x6174);
LAB_1000_018d:
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + (char)uVar17;
    cVar12 = (char)((uint)in_CX >> 8);
    pbVar2 = puVar31 + (int)puVar33;
    bVar11 = (byte)in_CX & 7;
    *pbVar2 = *pbVar2 << bVar11 | *pbVar2 >> 8 - bVar11;
    *(char *)((int)in_BX + (int)puVar33) =
         *(char *)((int)in_BX + (int)puVar33) + (char)uVar17 + cVar12;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    pbVar2 = (byte *)((int)in_BX + (int)puVar33);
    bVar11 = *pbVar2;
    bVar13 = *pbVar2;
    *pbVar2 = *pbVar2 + 0x42;
    *(uint *)((int)puVar29 + -2) =
         (uint)(in_NT & 1) * 0x4000 | (uint)SCARRY1(bVar13,'B') * 0x800 | (uint)(in_IF & 1) * 0x200
         | (uint)(in_TF & 1) * 0x100 | (uint)((char)*pbVar2 < '\0') * 0x80 |
         (uint)(*pbVar2 == 0) * 0x40 | (uint)(in_AF & 1) * 0x10 |
         (uint)((POPCOUNT(*pbVar2) & 1U) == 0) * 4 | (uint)(0xbd < bVar11);
    iVar21 = iVar21 + 1;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + 'B';
    puVar28 = (undefined2 *)(*(int *)((int)puVar33 + 0x61) * 0x6174);
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + -0x7c;
    puVar31[(int)puVar33] = puVar31[(int)puVar33];
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + -0x7c;
    puVar31 = puVar31 + 1;
    pbVar2 = (byte *)((int)in_BX + (int)puVar33);
    bVar11 = *pbVar2;
    *pbVar2 = *pbVar2 + 0x84;
    cVar14 = (0x7b < bVar11) + -0x7c;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
    puVar31[(int)puVar33] = puVar31[(int)puVar33] + '\x01';
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
    iVar16 = CONCAT11((char)(uVar17 >> 8),cVar14) + 1;
    bVar13 = (byte)iVar16;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33);
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    pbVar2 = (byte *)((int)in_BX + (int)puVar33);
    bVar11 = *pbVar2;
    *pbVar2 = *pbVar2 + bVar13;
    out(iVar21,iVar16);
    in_AF = 9 < (bVar13 & 0xf) | in_AF;
    bVar15 = bVar13 + in_AF * '\x06';
    uVar17 = *(uint *)((int)in_BX + (int)puVar33);
    ((char *)((int)in_BX + (int)puVar33))[0x45] =
         ((char *)((int)in_BX + (int)puVar33))[0x45] + (char)((uint)iVar21 >> 8);
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar12;
    uVar17 = CONCAT11((char)((uint)iVar16 >> 8),
                      bVar15 + (0x90 < (bVar15 & 0xf0) |
                               CARRY1(bVar11,bVar13) | in_AF * (0xf9 < bVar15)) * '`') | uVar17 |
             *(uint *)((int)in_BX + (int)puVar33);
    puVar31[(int)puVar33] = puVar31[(int)puVar33] + (char)iVar21;
  }
  else {
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    (puVar31 + (int)ppcVar35)[0x7b] = (puVar31 + (int)ppcVar35)[0x7b] + cVar14;
    iVar21 = iVar21 + 1;
    pbVar2 = (byte *)((int)in_BX + (int)puVar33);
    bVar13 = *pbVar2;
    *pbVar2 = *pbVar2 + bVar11;
    *(char *)((int)in_BX + (int)puVar33) =
         *(char *)((int)in_BX + (int)puVar33) + bVar11 + CARRY1(bVar13,bVar11);
    pcVar4 = (char *)((int)in_BX + (int)puVar33);
    cVar14 = *pcVar4;
    *pcVar4 = *pcVar4 + bVar11;
    puVar29 = puVar25;
    if (SCARRY1(cVar14,bVar11) != *pcVar4 < '\0') goto LAB_1000_018d;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    iVar16 = CONCAT11(cVar19,bVar11);
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar11;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar19;
    pbVar2 = (byte *)((int)in_BX + (int)puVar33);
    bVar13 = *pbVar2;
    *pbVar2 = *pbVar2 + bVar11;
    bVar15 = *pbVar2;
    puVar25[-1] = iVar16;
    puVar25[-2] = in_CX;
    puVar25[-3] = iVar21;
    puVar25[-4] = in_BX;
    puVar25[-5] = puVar25;
    puVar25[-6] = puVar31;
    puVar25[-7] = puVar33;
    puVar25[-8] = ppcVar35;
    puVar29 = puVar25 + -8;
    if (CARRY1(bVar13,bVar11)) {
LAB_1000_01c5_2:
      cVar14 = (char)iVar16;
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14;
      uVar17 = CONCAT11((char)((uint)iVar16 >> 8),cVar14 * '\x02');
      *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + cVar14 * '\x02';
      goto LAB_1000_018d;
    }
    ppcVar35 = (code **)puVar25[-8];
    puVar33 = (uint *)puVar25[-7];
    puVar31 = (undefined *)puVar25[-6];
    in_BX = (int *)puVar25[-4];
    iVar21 = puVar25[-3];
    in_CX = puVar25[-2];
    iVar16 = puVar25[-1];
    puVar29 = puVar25;
    if (bVar15 == 0) goto LAB_1000_01c5_2;
    pbVar2 = (byte *)((int)in_BX + (int)puVar33);
    bVar11 = *pbVar2;
    bVar13 = (byte)iVar16;
    *pbVar2 = *pbVar2 + bVar13;
    puVar31[(int)puVar33] = (puVar31[(int)puVar33] - (char)in_BX) - CARRY1(bVar11,bVar13);
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    ((char *)((int)in_BX + (int)puVar33))[0x42] =
         ((char *)((int)in_BX + (int)puVar33))[0x42] + (char)iVar21;
    *(char *)puVar33 = *(char *)puVar33 + (char)in_BX;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    ((char *)((int)in_BX + (int)puVar33))[0x42] =
         ((char *)((int)in_BX + (int)puVar33))[0x42] + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13;
    *(char *)((int)in_BX + (int)puVar33) = *(char *)((int)in_BX + (int)puVar33) + bVar13 + 1;
    ppcVar35 = (code **)*puVar25;
    puVar33 = (uint *)puVar25[1];
    puVar31 = (undefined *)puVar25[2];
    in_BX = (int *)puVar25[4];
    iVar21 = puVar25[5];
    in_CX = puVar25[6];
    uVar17 = puVar25[7];
    puVar29 = puVar25 + 8;
    puVar28 = puVar25 + 8;
    if (iVar16 != -2) goto LAB_1000_018d;
  }
  iVar16 = (int)in_BX + 1;
  bVar13 = (byte)uVar17;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar13;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar13;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar13;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar13;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar13;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar13;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar13;
  uVar20 = (undefined)(uVar17 >> 8);
  bVar11 = bVar13 * '\x02';
  uVar17 = CONCAT11(uVar20,bVar11);
  if (CARRY1(bVar13,bVar13)) {
LAB_1000_0276:
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
  }
  else {
    if (CARRY1(bVar13,bVar13)) {
      *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
      *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
      *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
      *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
      *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
      *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
      *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
      goto LAB_1000_0276;
    }
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    pcVar4 = (char *)((int)puVar33 + (int)in_BX + 0x31);
    *pcVar4 = *pcVar4 + (char)((uint)iVar21 >> 8);
    pcVar4 = (char *)(iVar16 + (int)puVar33);
    *pcVar4 = *pcVar4 + bVar11;
    in_CX = in_CX + -1;
    puVar34 = puVar33;
    if (in_CX != 0 && *pcVar4 != '\0') {
LAB_1000_025f:
      cVar14 = (char)uVar17;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)((int)ppcVar35 + -0x75) = *(char *)((int)ppcVar35 + -0x75) + (byte)iVar21;
      cVar14 = in(iVar21);
      puVar30 = (undefined *)puVar28;
      puVar32 = puVar31;
      puVar33 = puVar34;
      goto code_r0x000103c3;
    }
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    bVar11 = bVar11 ^ *(byte *)(iVar16 + (int)puVar33);
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + bVar11;
    pbVar2 = (byte *)(iVar16 + (int)puVar33);
    bVar36 = CARRY1(*pbVar2,bVar11 + 1);
    *pbVar2 = *pbVar2 + bVar11 + 1;
    uVar17 = CONCAT11(uVar20,bVar11) + 2;
    if (!bVar36) {
      ppcVar8 = ppcVar35;
      ppcVar35 = (code **)((int)ppcVar35 + 1);
      uVar20 = in(iVar21);
      *(undefined *)ppcVar8 = uVar20;
      puVar34 = puVar33 + 1;
      out(*puVar33,iVar21);
      puVar3 = (uint *)(iVar16 + (int)puVar34);
      *puVar3 = *puVar3 + (uint)bVar36 * ((uVar17 & 3) - (*puVar3 & 3));
      pcVar4 = (char *)((int)puVar34 + (int)in_BX + -0x5d);
      cVar14 = (char)uVar17;
      *pcVar4 = *pcVar4 + cVar14;
      *(byte *)(iVar16 + (int)ppcVar35) = *(byte *)(iVar16 + (int)ppcVar35) & (byte)iVar21;
      *(char *)((int)puVar33 + 7) = *(char *)((int)puVar33 + 7) + (char)(uVar17 >> 8);
      *(char *)(puVar33 + 0x28) = *(char *)(puVar33 + 0x28) + (char)((uint)in_CX >> 8);
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      puVar31[(int)puVar34] = puVar31[(int)puVar34] + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + cVar14;
      goto LAB_1000_025f;
    }
  }
  cVar14 = (char)uVar17;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  puVar30 = (undefined *)((int)puVar28 + -2);
  puVar32 = (undefined *)((int)puVar28 + -2);
  *(undefined2 *)((int)puVar28 + -2) = puVar31;
code_r0x000103c3:
  *(int *)(puVar30 + -0x3e) = iVar16;
  *(uint **)(puVar30 + -0x40) = puVar33;
  *(code ***)(puVar30 + -0x42) = ppcVar35;
  ppcVar35[-4] = (code *)0x0;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  ppcVar35[-2] = (code *)0x0;
  *(char *)(iVar16 + (int)puVar33) = *(char *)(iVar16 + (int)puVar33) + cVar14;
  pcVar9 = *ppcVar35;
  *(undefined2 *)(puVar30 + -0x44) = 0x3d9;
  uVar37 = (*pcVar9)();
  uVar22 = (undefined2)((ulong)uVar37 >> 0x10);
  iVar21 = (int)uVar37;
  puVar34 = (uint *)((int)ppcVar35 + 1);
  uVar20 = in(uVar22);
  *(undefined *)ppcVar35 = uVar20;
  puVar3 = (uint *)(iVar16 + iVar21);
  uVar17 = *puVar3;
  puRam00001148 = puVar33;
  *puVar3 = *puVar3 - 0x5f;
  *(char **)(puVar32 + (int)puVar34 + 0x2b00) =
       (char *)((int)puVar33 +
               (int)(*(char **)(puVar32 + (int)puVar34 + 0x2b00) + ((0x5e < uVar17) - 1)));
  pcVar18 = (char *)((int)puVar33 + -0x4fb9);
  pbVar2 = (byte *)(iVar16 + iVar21);
  bVar11 = *pbVar2;
  *pbVar2 = *pbVar2 + 0xa3;
  *(char **)(puVar32 + (int)puVar34 + -32000) =
       pcVar18 + (int)(*(char **)(puVar32 + (int)puVar34 + -32000) + (0x5c < bVar11));
  pcVar4 = (char *)(iVar16 + iVar21);
  cVar14 = *pcVar4;
  *pcVar4 = *pcVar4 + '\x01';
  if (SCARRY1(cVar14,'\x01') == *pcVar4 < '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  do {
    *(char *)(iVar16 + iVar21) = *(char *)(iVar16 + iVar21) + (char)pcVar18;
    uVar17 = *puVar34;
    ppcVar1 = (char **)(puVar32 + (int)puVar34 + 0x1100);
    pcVar5 = *ppcVar1;
    pcVar6 = *ppcVar1;
    *ppcVar1 = pcVar6 + (int)pcVar18 + (uVar17 < 0x5c);
    if ((SCARRY2((int)pcVar5,(int)pcVar18) !=
        SCARRY2((int)(pcVar6 + (int)pcVar18),(uint)(uVar17 < 0x5c))) == (int)*ppcVar1 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
                    // WARNING: Read-only address (ram,0x000100b6) is written
      halt_baddata();
    }
    *(char *)(iVar16 + iVar21) = *(char *)(iVar16 + iVar21) + (char)pcVar18;
    pcVar4 = (char *)(iVar16 + iVar21);
    *pcVar4 = *pcVar4 + -0x7e;
    if (*pcVar4 == '\0') {
      return;
    }
    *(char *)(iVar16 + iVar21) = *(char *)(iVar16 + iVar21) + -0x7e;
    pcVar18 = (char *)CONCAT11((char)((uint)pcVar18 >> 8),0x82);
    pcVar4 = (char *)(iVar16 + iVar21);
    *pcVar4 = *pcVar4 + -0x7e;
    bVar36 = *pcVar4 == '\0';
    while( true ) {
      if (!bVar36) goto code_r0x00010446;
      *(char *)(iVar16 + iVar21) = *(char *)(iVar16 + iVar21) + (char)pcVar18;
      *puVar34 = 0xb044;
      *(char *)(iVar16 + iVar21) = *(char *)(iVar16 + iVar21) + '\x01';
      *(char *)(iVar16 + iVar21) = *(char *)(iVar16 + iVar21) + (char)pcVar18;
      pcVar4 = (char *)((int)puVar34 + iVar16 + 0x1148);
      cVar14 = (char)((uint)pcVar18 >> 8);
      *pcVar4 = *pcVar4 + cVar14;
      *(int *)(iVar16 + iVar21) = *(int *)(iVar16 + iVar21) + -0x77;
      if (in_CX + -1 != 0 && puVar32 + 1 != (undefined *)0x0) break;
      puVar32 = puVar32 + 2;
      cVar12 = in(0);
      pcVar18 = (char *)CONCAT11(cVar14,cVar12);
      *(char *)(iVar16 + iVar21) = *(char *)(iVar16 + iVar21) + cVar12;
      cVar14 = (char)((uint)iVar16 >> 8) + (char)iVar16;
      iVar16 = CONCAT11(cVar14,(char)iVar16);
      bVar36 = cVar14 == '\0';
      puVar3 = puVar34;
      puVar34 = puVar34 + 1;
      uVar17 = in(uVar22);
      *puVar3 = uVar17;
      in_CX = in_CX + -2;
      if (in_CX == 0 || bVar36) {
code_r0x00010446:
        *(int *)(iVar16 + iVar21) = *(int *)(iVar16 + iVar21) + -0x5f;
        *(char *)(iVar16 + (int)puVar34) = *(char *)(iVar16 + (int)puVar34) + '\x01';
        return;
      }
    }
    *(int *)(iVar16 + iVar21) = *(int *)(iVar16 + iVar21) + 0x11;
    in_CX = in_CX + -1;
    puVar32 = puVar32 + 1;
  } while( true );
}


