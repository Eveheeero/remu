use capstone::{
    prelude::{BuildsCapstone, BuildsCapstoneSyntax},
    Insn,
};

#[derive(Clone, Copy)]
pub struct Instruction {
    pub mnemonix: Option<&'static str>,
    pub operands: Option<&'static str>,
}

static mut CS: Option<capstone::Capstone> = None;

#[inline]
fn inst_to_output(inst: &Insn) -> Instruction {
    let mnemonix = if let Some(mnemonic) = &inst.mnemonic() {
        Some(mnemonic_to_static(mnemonic))
    } else {
        None
    };
    let operands = if let Some(operands) = &inst.op_str() {
        Some(operands_to_static(operands))
    } else {
        None
    };
    Instruction { mnemonix, operands }
}

#[inline]
#[allow(dead_code)]
fn str_to_static(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

#[inline]
fn mnemonic_to_static(s: &str) -> &'static str {
    match s {
        "mov" => "mov",
        "add" => "add",
        "sub" => "sub",
        "xor" => "xor",
        "and" => "and",
        "or" => "or",
        "cmp" => "cmp",
        "test" => "test",
        "lea" => "lea",
        "push" => "push",
        "pop" => "pop",
        "call" => "call",
        "ret" => "ret",
        "jmp" => "jmp",
        "jz" => "jz",
        "jnz" => "jnz",
        "jg" => "jg",
        "jge" => "jge",
        "jl" => "jl",
        "jle" => "jle",
        "ja" => "ja",
        "jae" => "jae",
        "jb" => "jb",
        "jbe" => "jbe",
        "loop" => "loop",
        "loope" => "loope",
        "loopne" => "loopne",
        "nop" => "nop",
        "int" => "int",
        "hlt" => "hlt",
        "cli" => "cli",
        "sti" => "sti",
        "cld" => "cld",
        "std" => "std",
        "inc" => "inc",
        "dec" => "dec",
        "mul" => "mul",
        "imul" => "imul",
        "div" => "div",
        "idiv" => "idiv",
        "shl" => "shl",
        "shr" => "shr",
        "sar" => "sar",
        "rol" => "rol",
        "ror" => "ror",
        "rcl" => "rcl",
        "rcr" => "rcr",
        "xchg" => "xchg",
        "bswap" => "bswap",
        "cbw" => "cbw",
        "cwd" => "cwd",
        "cwde" => "cwde",
        "cdq" => "cdq",
        "cdqe" => "cdqe",
        "xlat" => "xlat",
        "xlatb" => "xlatb",
        "in" => "in",
        "out" => "out",
        "insb" => "insb",
        "insw" => "insw",
        "insd" => "insd",
        "outsb" => "outsb",
        "outsw" => "outsw",
        "outsd" => "outsd",
        "movsb" => "movsb",
        "movsw" => "movsw",
        "movsd" => "movsd",
        "movsx" => "movsx",
        "movzx" => "movzx",
        "lodsb" => "lodsb",
        "lodsw" => "lodsw",
        "lodsd" => "lodsd",
        "stosb" => "stosb",
        "stosw" => "stosw",
        "stosd" => "stosd",
        "scasb" => "scasb",
        "scasw" => "scasw",
        "scasd" => "scasd",
        "cmpsb" => "cmpsb",
        "cmpsw" => "cmpsw",
        "cmpsd" => "cmpsd",
        "seta" => "seta",
        "setae" => "setae",
        "setb" => "setb",
        "setbe" => "setbe",
        "setc" => "setc",
        "sete" => "sete",
        "setg" => "setg",
        "setge" => "setge",
        "setl" => "setl",
        "setle" => "setle",
        "setna" => "setna",
        "setnae" => "setnae",
        "setnb" => "setnb",
        "setnbe" => "setnbe",
        "setnc" => "setnc",
        "setne" => "setne",
        "setng" => "setng",
        "setnge" => "setnge",
        "setnl" => "setnl",
        "setnle" => "setnle",
        "setno" => "setno",
        "setnp" => "setnp",
        "setns" => "setns",
        "setnz" => "setnz",
        "seto" => "seto",
        "setp" => "setp",
        "setpe" => "setpe",
        "setpo" => "setpo",
        "sets" => "sets",
        "setz" => "setz",
        "cmova" => "cmova",
        "cmovae" => "cmovae",
        "cmovb" => "cmovb",
        "cmovbe" => "cmovbe",
        "cmovc" => "cmovc",
        "cmove" => "cmove",
        "cmovg" => "cmovg",
        "cmovge" => "cmovge",
        "cmovl" => "cmovl",
        "cmovle" => "cmovle",
        "cmovna" => "cmovna",
        "cmovnae" => "cmovnae",
        "cmovnb" => "cmovnb",
        "cmovnbe" => "cmovnbe",
        "cmovnc" => "cmovnc",
        "cmovne" => "cmovne",
        "cmovng" => "cmovng",
        "cmovnge" => "cmovnge",
        "cmovnl" => "cmovnl",
        "cmovnle" => "cmovnle",
        "cmovno" => "cmovno",
        "cmovnp" => "cmovnp",
        "cmovns" => "cmovns",
        "cmovnz" => "cmovnz",
        "cmovo" => "cmovo",
        "cmovp" => "cmovp",
        "cmovpe" => "cmovpe",
        "cmovpo" => "cmovpo",
        "cmovs" => "cmovs",
        "cmovz" => "cmovz",
        "fadd" => "fadd",
        "faddp" => "faddp",
        "fiadd" => "fiadd",
        "fsub" => "fsub",
        "fsubp" => "fsubp",
        "fisub" => "fisub",
        "fsubr" => "fsubr",
        "fsubrp" => "fsubrp",
        "fisubr" => "fisubr",
        "fmul" => "fmul",
        "fmulp" => "fmulp",
        "fimul" => "fimul",
        "fdiv" => "fdiv",
        "fdivp" => "fdivp",
        "fidiv" => "fidiv",
        "fdivr" => "fdivr",
        "fdivrp" => "fdivrp",
        "fidivr" => "fidivr",
        _ => panic!("Unknown instruction: {}", s),
    }
}

#[inline]
fn operands_to_static(s: &str) -> &'static str {
    match s {
        "eax" => "eax",
        "ebx" => "ebx",
        "ecx" => "ecx",
        "edx" => "edx",
        "esi" => "esi",
        "edi" => "edi",
        "esp" => "esp",
        "ebp" => "ebp",
        "rax" => "rax",
        "rbx" => "rbx",
        "rcx" => "rcx",
        "rdx" => "rdx",
        "rsi" => "rsi",
        "rdi" => "rdi",
        "rsp" => "rsp",
        "rbp" => "rbp",
        "al" => "al",
        "bl" => "bl",
        "cl" => "cl",
        "dl" => "dl",
        "sil" => "sil",
        "dil" => "dil",
        "spl" => "spl",
        "bpl" => "bpl",
        "ah" => "ah",
        "bh" => "bh",
        "ch" => "ch",
        "dh" => "dh",
        "ax" => "ax",
        "bx" => "bx",
        "cx" => "cx",
        "dx" => "dx",
        "si" => "si",
        "di" => "di",
        "sp" => "sp",
        "bp" => "bp",
        "st0" => "st0",
        "st1" => "st1",
        "st2" => "st2",
        "st3" => "st3",
        "st4" => "st4",
        "st5" => "st5",
        "st6" => "st6",
        "st7" => "st7",
        "mm0" => "mm0",
        "mm1" => "mm1",
        "mm2" => "mm2",
        "mm3" => "mm3",
        "mm4" => "mm4",
        "mm5" => "mm5",
        "mm6" => "mm6",
        "mm7" => "mm7",
        "xmm0" => "xmm0",
        "xmm1" => "xmm1",
        "xmm2" => "xmm2",
        "xmm3" => "xmm3",
        "xmm4" => "xmm4",
        "xmm5" => "xmm5",
        "xmm6" => "xmm6",
        "xmm7" => "xmm7",
        "xmm8" => "xmm8",
        "xmm9" => "xmm9",
        "xmm10" => "xmm10",
        "xmm11" => "xmm11",
        "xmm12" => "xmm12",
        "xmm13" => "xmm13",
        "xmm14" => "xmm14",
        "xmm15" => "xmm15",
        _ => panic!("Unknown operand: {}", s),
    }
}

#[inline]
pub unsafe fn disas_i386_big(base: u64, offset: &[u8]) -> Result<Instruction, ()> {
    if CS.is_none() {
        CS = Some(
            capstone::Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .syntax(capstone::arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .unwrap(),
        );
    }
    let cs = CS.as_ref().unwrap();
    let insns = cs.disasm_count(offset, base, 1).unwrap();
    let insn = match insns.first() {
        Some(insn) => insn,
        None => return Err(()),
    };
    Ok(inst_to_output(insn))
}
