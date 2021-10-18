#include <Windows.h>
#include <iostream>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#pragma comment(lib, "zydis.lib")

void* allocate_memory_close_to_address(void* address, size_t size)
{
	SYSTEM_INFO system_info; GetSystemInfo(&system_info);
	const uintptr_t page_size = system_info.dwPageSize;

	uintptr_t start_adress = (uintptr_t(address) & ~(page_size - 1));
	uintptr_t min = min(start_adress - 0x7FFFFF00, (uintptr_t)system_info.lpMinimumApplicationAddress);
	uintptr_t max = max(start_adress + 0x7FFFFF00, (uintptr_t)system_info.lpMaximumApplicationAddress);

	uintptr_t start_page = (start_adress - (start_adress % page_size));

	uintptr_t page = 1;
	while (true)
	{
		uintptr_t byte_offset = page * page_size;
		uintptr_t high = start_page + byte_offset;
		uintptr_t low = (start_page > byte_offset) ? start_page - byte_offset : 0;

		bool stop_point = high > max && low < min;

		if (!low)
			continue;

		if (high < max)
		{
			void* outAddr = VirtualAlloc((void*)high, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (low > min)
		{
			void* outAddr = VirtualAlloc((void*)low, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		page += 1;

		if (stop_point)
			break;
	}

	return nullptr;
}

struct instruction_t {
	instruction_t* next;
	instruction_t* prev;
	ZydisDecodedInstruction zyinstruction;
	uintptr_t runtimeaddy;
	DWORD length;
	BYTE* raw_data;
};
typedef decltype(&MessageBoxA)ourmsgbox;


int main() {
	uintptr_t address_to_call = (uintptr_t)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);


	instruction_t* start = new instruction_t;
	instruction_t* end = start;
	start->prev = start->next = nullptr;

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;
	/*
	Collect instructions and link them together
	*/
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(address_to_call + offset), INT_MAX - offset,
		&instruction)))
	{
		instruction_t* new_instruction = new instruction_t;
		new_instruction->length = instruction.length;
		new_instruction->raw_data = new BYTE[instruction.length];
		memcpy(new_instruction->raw_data, (void*)(address_to_call + offset), new_instruction->length);
		new_instruction->zyinstruction = instruction;
		new_instruction->runtimeaddy = address_to_call + offset;
		new_instruction->prev = end;
		new_instruction->next = nullptr;
		end->next = new_instruction;
		end = new_instruction;
		offset += instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_INT3)
			break;
	}
	/*
	Allocate a buffer for our function
	*/
	void* new_base = allocate_memory_close_to_address((void*)address_to_call, offset);
	/*
	Fix RIP relative instructions. This example only covers a few amount (for MessageBoxA)
	*/
	for (instruction_t* inst = start->next; inst; inst = inst->next) {
		int current_offset = (inst->runtimeaddy - address_to_call);
		memcpy((void*)((uintptr_t)new_base + current_offset), inst->raw_data, inst->length);
		ZydisMnemonic mnemonic = inst->zyinstruction.mnemonic;
		switch (mnemonic) {
		case ZYDIS_MNEMONIC_CMP: {
			if (inst->length == 7) { //cmp relative rip
				signed int dst = *(signed int*)(inst->raw_data + 3);
				uintptr_t original_destination = inst->runtimeaddy + dst + inst->length;
				signed int new_destination = original_destination - (uintptr_t)new_base - current_offset - inst->length; //Todo check if allocation is > func or < func
				*(signed int*)((uintptr_t)new_base + current_offset + 3) = new_destination;
			}
			break;
		}
		case ZYDIS_MNEMONIC_CMPXCHG: {
			if (inst->length == 9) { //cmpxchg relative rip
				signed int dst = *(signed int*)(inst->raw_data + 5);
				uintptr_t original_destination = inst->runtimeaddy + dst + inst->length;
				signed int new_destination = original_destination - (uintptr_t)new_base - current_offset - inst->length;//Todo check if allocation is > func or < func
				*(signed int*)((uintptr_t)new_base + current_offset + 5) = new_destination;
			}
			break;
		}
		case ZYDIS_MNEMONIC_MOV: {
			if (inst->length == 7) { //mov relative rip
				signed int dst = *(signed int*)(inst->raw_data + 3);
				uintptr_t original_destination = inst->runtimeaddy + dst + inst->length;
				signed int new_destination = original_destination - (uintptr_t)new_base - current_offset - inst->length;//Todo check if allocation is > func or < func
				*(signed int*)((uintptr_t)new_base + current_offset + 3) = new_destination;
			}
			break;
		}
		case ZYDIS_MNEMONIC_CALL: {
			if (inst->length == 5) { //mov relative rip
				signed int dst = *(signed int*)(inst->raw_data + 1);
				uintptr_t original_destination = inst->runtimeaddy + dst + inst->length;
				signed int new_destination = original_destination - (uintptr_t)new_base - current_offset - inst->length;//Todo check if allocation is > func or < func
				*(signed int*)((uintptr_t)new_base + current_offset + 1) = new_destination;
			}
			break;
		}
		}
	}

	ourmsgbox msg = (ourmsgbox)new_base;
	msg(0, "Call from allocated memory", " ", 0);
	system("pause");
	MessageBoxA(0, "Call from IAT", " ", 0);
	
}
