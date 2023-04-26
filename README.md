#  Firmware best practice checker

This static analysis tool utilizes a cppcheck dump file to validate fundamental code rules for an embedded system firmware. 
The rules are a reflection of the best practices in embedded system firmware design and complement other standards such as MISRA-C, 
which solely focuses on C language best practices.

The tool can currently verify the following:

-   Global and local variables
-   Interrupt Service Routines
-   Header files.

## Current supported check

| rule | Type    | Short                                         |
|------|---------|-----------------------------------------------|
| 1.1  | vars    | Global var accessed from ISR must be volatile |
| 1.2  | vars    | Only IRQ vars shall be volatiles              |
| 1.3  | vars    | Only use global vars in IRQ                   |
| 2.1  | ISR     | No delay call in ISR                          |
| 2.2  | ISR     | No oled call in ISR                           |
| 2.3  | ISR     | No printf call in ISR                         |
| 2.4  | ISR     | No while/for loops in ISR                     |
| 2.5  | ISR     | Complex code in ISR                           |
| 3.1  | .h file | No code inside .h                             |
| 3.2  | .h file | Missing include guard                         |

## Using

To use you first need to generate a cppcheck dump file:

``` sh
cppcheck --enable=all --dump .
```

Than run:

``` sh
python3 check.py .
```

## Arguments 

- `--print-table`: Format check as a table
- `--output-file=`: Write the result to a csv file


