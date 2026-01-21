# ida_ieee

IEEE floating point functions.

## Constants

- `FPVAL_NWORDS`: number of words in fpvalue_t
- `FPV_BADARG`: wrong value of max_exp
- `FPV_NORM`: regular value
- `FPV_NAN`: NaN.
- `FPV_PINF`: positive infinity
- `FPV_NINF`: negative infinity
- `REAL_ERROR_OK`: no error
- `REAL_ERROR_FORMAT`: realcvt: not supported format for current .idp
- `REAL_ERROR_RANGE`: realcvt: number too big (small) for store (mem NOT modified)
- `REAL_ERROR_BADDATA`: realcvt: illegal real data for load (IEEE data not filled)
- `REAL_ERROR_FPOVER`: floating overflow or underflow
- `REAL_ERROR_BADSTR`: asctoreal: illegal input string
- `REAL_ERROR_ZERODIV`: ediv: divide by 0
- `REAL_ERROR_INTOVER`: eetol*: integer overflow
- `cvar`
- `MAXEXP_FLOAT`
- `MAXEXP_DOUBLE`
- `MAXEXP_LNGDBL`
- `IEEE_EXONE`: The exponent of 1.0.
- `E_SPECIAL_EXP`: Exponent in fpvalue_t for NaN and Inf.
- `IEEE_NI`: Number of 16 bit words in eNI.
- `IEEE_E`: Array offset to exponent.
- `IEEE_M`: Array offset to high guard word
- `EZERO`
- `EONE`
- `ETWO`

## Classes Overview

- `fpvalue_shorts_array_t`
- `fpvalue_t`

## Functions Overview

- `ecleaz(x: eNI) -> None`