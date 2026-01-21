# ida_range

Contains the definition of range_t.

A range is a non-empty continuous range of addresses (specified by its start and end addresses, the end address is excluded from the range).
Ranges are stored in the Btree part of the IDA database. To learn more about Btrees (Balanced Trees): [http://www.bluerwhite.org/btree/](http://www.bluerwhite.org/btree/)

## Constants

- `RANGE_KIND_UNKNOWN`
- `RANGE_KIND_FUNC`: func_t
- `RANGE_KIND_SEGMENT`: segment_t
- `RANGE_KIND_HIDDEN_RANGE`: hidden_range_t

## Classes Overview

- `rangevec_base_t`
- `array_of_rangesets`
- `range_t`
- `rangevec_t`
- `rangeset_t`

## Functions Overview

- `range_t_print(cb: range_t) -> str`: Helper function. Should not be called directly!