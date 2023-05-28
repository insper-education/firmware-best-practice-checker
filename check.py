#!/usr/bin/env python3
import argparse
import csv
import os
import sys
from glob import glob

from sty import bg, ef, fg, rs
from tabulate import tabulate

import cppcheckdata
from misra import *
from misra import (get_type_conversion_to_from, getArguments, getEssentialType,
                   is_header, isFunctionCall, isKeyword)

IRQ_NAMES = ["callback", "Handler"]
DELAY_FUNCTIONS = ["delay_", "delay_ms", "delay_us", "delay_s"]
OLED_FUNCTIONS = ["gfx_mono_"]
PRINTF_FUNCTIONS = ["printf", "sprintf"]

RULE_1_1_EXCEPTIONS = ["lv_obj_t", "SemaphoreHandle_t", "TimerHandle_t", "QueueHandle_t"]
RULE_1_3_EXCEPTIONS = ["lv_obj_t", "SemaphoreHandle_t", "TimerHandle_t", "QueueHandle_t"]

RULE_1_1_ERRO_TXT = [
    "All global variables that are accessed from IRQ must be declared as volatile to ensure that the compailer will not optimize it out.",
    "All global variables that are updated in IRQ or Callback should be volatile",
]

RULE_1_2_ERRO_TXT = [
    "Local variables should not be declared as volatile to ensure that the compailer will optimize it out.",
    "Local variables should NOT be volatile",
]

RULE_1_3_ERRO_TXT = [
    "Global variables should generally be avoided, except when necessary or when dealing with IRQs",
    "Do not use global vars outside IRQ",
]

RULE_2_1_ERRO_TXT = [
    "ISR shall be fast as possible, forbidden use of delay functions inside hardware interruption",
    "Forbidden use of delay functions within IRQ",
]

RULE_2_2_ERRO_TXT = [
    "ISR shall be fast as possible, forbidden OLED update inside hardware interruption",
    "Forbidden use of gfx_mono_... functions within IRQ",
]

RULE_2_3_ERRO_TXT = [
    "ISR shall be fast as possible, forbidden PRINTF/SPRINTF inside hardware interruption",
    "Forbidden use of printf/sprintf functions within IRQ",
]

RULE_2_4_ERRO_TXT = [
    "ISR shall be fast as possible avoid the use of while and for loops",
    "Forbidden use of loops/While within IRQ",
]

RULE_3_1_ERRO_TXT = [
    "Header file (.h) contents should be protected against multiple inclusions (include guard)",
    "Header file contents should be protected against multiple inclusions (include guard)",
]

RULE_3_2_ERRO_TXT = [
    "Do not implement code inside .h file",
    "Forbidden implementation of C code in .h file",
]


class EmbeddedC:
    def __init__(self, data, repoName, filePath):
        self.data = data
        self.repoName = repoName
        self.filePath = filePath
        self.fileName = os.path.basename(filePath)
        self.erroTotal = 0
        self.erroLog = []
        self.cfg = []

    def updateCfg(self, cfg):
        self.cfg = cfg

    def getVars(self):
        return self.cfg.variables

    def getScopes(self):
        return self.cfg.scopes

    def getPreviousScope(self, scopeId):
        cnt = 0
        scopes = self.getScopes()
        for scope in scopes:
            if scope.Id == scopeId:
                return scopes[cnt - 1]
            cnt = cnt + 1

    def getOnlyGlobalVars(self):
        varList = []
        for var in self.cfg.variables:
            if var.isGlobal:
                varList.append(var)
        return varList

    def getScope(self, token):
        scope = token.scope
        while scope.type != 'Function':
            scope = self.getPreviousScope(scope.Id)
        return scope

    def getVarAss(self, token):
        var = None
        if token.astOperand1.str == '[':
            t = token.astOperand1
            while t.variable == None:
                t = t.astOperand1
            var = t.variable
        else:
            var = token.astOperand1.variable
        return var

    def getAllVarAssigments(self):
        allVarAssigments = []

        for token in self.cfg.tokenlist:
            if token.isAssignmentOp and token.scope.type != 'Global':
                variable = self.getVarAss(token)
                if variable is None:
                    continue

                scope = self.getScope(token)
                allVarAssigments.append({
                    'className': scope.className,
                    'variable': variable,
                    'line': token.linenr,
                })
        return allVarAssigments

    def getOnlyGolbalVarAssigments(self):
        allVarAssigments = self.getAllVarAssigments()
        globalVars = self.getOnlyGlobalVars()

        # create list of global var assigments
        globalVarsAssigments = []
        for var in globalVars:
            for ass in allVarAssigments:
                if var.Id == ass['variable'].Id:
                    globalVarsAssigments.append(ass)
        return globalVarsAssigments

    def isFunctionIRQ(self, f):
        res = [ele for ele in IRQ_NAMES if (ele in f.name)]
        return True if res else False

    def createFunctionIrqList(self):
        irqFuncList = []
        for f in self.cfg.functions:
            if self.isFunctionIRQ(f):
                if f != None:
                    irqFuncList.append(f)

        for token in self.cfg.tokenlist:
            if isFunctionCall(token):
                if token.previous.str == "pio_handler_set":
                    f = getArguments(token)[-1]
                    if f.function != None:
                        irqFuncList.append(f.function)

        return irqFuncList

    def printRuleViolation(self, ruleN, where, text):
        self.erroTotal = self.erroTotal + 1
        erroText = text[0]
        self.erroLog.append({
                "repo": self.repoName,
                "file": self.fileName,
                "rule": ruleN,
                "file": where,
                "text": erroText,
            })
        print(f" - [{fg.red}RULE {ruleN} VIOLATION{fg.rs}] {where} \r\n\t {erroText}")


    def rule_1_1(self):
        """
        Rule 1: All global variables assigment in IRQ or Callback should be volatile
        """
        erro = 0

        assigments = self.getOnlyGolbalVarAssigments()
        irqFuncs = self.createFunctionIrqList()

        # create lisr of function IRQ name
        irqFuncClassNames = []
        for func in irqFuncs:
            irqFuncClassNames.append(func.name)

        varErroListId = []
        for ass in assigments:
            # excluce specific types exceptions (rtos, lcd)
            varType = ass['variable'].typeStartToken.str
            if [ele for ele in RULE_1_1_EXCEPTIONS if (ele in varType)]:
                continue

            # only check for var ass in IRQ functions
            if ass['className'] not in irqFuncClassNames:
                continue

            # skip duplicate error
            if ass['variable'].Id in varErroListId:
                continue

            if not ass["variable"].isVolatile:
                varName = ass["variable"].nameToken.str
                funcName = ass["className"]
                self.printRuleViolation(
                    "1_1",
                    f"variable {fg.blue}{varName}{fg.rs} in function {fg.blue}{funcName}{fg.rs}",
                    RULE_1_1_ERRO_TXT,
                )
                varErroListId.append(ass['variable'].Id)
                erro = erro + 1
        return erro

    def rule_1_2(self):
        """
        Rule 2: Do not use volatile in local var
        """

        erro = 0

        assigments = self.getAllVarAssigments()
        irqFuncs = self.createFunctionIrqList()

        # create lisr of function IRQ name
        irqFuncClassNames = []
        for func in irqFuncs:
            irqFuncClassNames.append(func.name)

        for ass in assigments:
            # exclue IRQ functions
            if ass['className'] in irqFuncClassNames:
                continue

            if ass["variable"].isVolatile and ass['variable'].isLocal:
                varName = ass["variable"].nameToken.str
                funcName = ass["className"]
                self.printRuleViolation(
                    "1_2",
                    f"variable {fg.blue}{varName}{fg.rs} in function {fg.blue}{funcName}{fg.rs}",
                    RULE_1_2_ERRO_TXT,
                )
                erro = erro + 1
        return erro

    def rule_1_3(self):
        """
        Rule 2: only use global vars in IRQ
        """
        erro = 0

        assigments = self.getOnlyGolbalVarAssigments()
        irqFuncs = self.createFunctionIrqList()

        # create lisr of function IRQ name
        irqFuncClassNames = []
        for func in irqFuncs:
            irqFuncClassNames.append(func.name)

        # create var list that are update in ISR
        varAssIsrIds = []
        for ass in assigments:
            if [ele for ele in irqFuncClassNames if (ele in ass['className'])]:
                varAssIsrIds.append(ass['variable'].Id)

        # interact in global vars only assigments
        varErroListId = []
        for ass in assigments:
            # excluce specific types exceptions (rtos, lcd)
            if ass['variable'].typeStartToken.str in RULE_1_3_EXCEPTIONS:
                continue

            # exclude var that are accessed in Isr
            if ass['variable'].Id in varAssIsrIds:
                continue

            # skip duplicate error
            if ass['variable'].Id in varErroListId:
                continue

            # erro print
            varName = ass['variable'].nameToken.str
            self.printRuleViolation(
                "1_3",
                f"global variable {fg.blue}{varName}{fg.rs}",
                RULE_1_3_ERRO_TXT,
            )
            varErroListId.append(ass['variable'].Id)
            erro = erro + 1

        return erro

    def rule_2_x(self, ruleN, ruleTxt, rule):
        """
        Rule 3: search for forbiten functions call inside ISR
        """
        erro = 0

        irqFuncs = self.createFunctionIrqList()
        for function in irqFuncs:
            for token in self.cfg.tokenlist:
                scope = self.getScope(token)
                if scope.function.Id == function.Id:
                    res = [ele for ele in rule if (ele in token.str)]
                    if res:
                        isrName = function.token.str
                        callName = token.str
                        self.printRuleViolation(
                            ruleN, f"function call to {fg.blue}{callName}{fg.rs} inside {fg.blue}{isrName}{fg.rs}", ruleTxt
                        )
                        erro = erro + 1
        return erro

    def rule_2_1(self):
        """
        Rule 2_1: No delay inside IRQ
        """
        return self.rule_2_x("2_1", RULE_2_1_ERRO_TXT, DELAY_FUNCTIONS)

    def rule_2_2(self):
        """
        Rule 2_2: No oled calls inside IRQ
        """
        return self.rule_2_x("2_2", RULE_2_2_ERRO_TXT, OLED_FUNCTIONS)

    def rule_2_3(self):
        """
        Rule 2_3: No printf calls inside IRQ
        """
        return self.rule_2_x("2_3", RULE_2_3_ERRO_TXT, PRINTF_FUNCTIONS)

    def rule_2_4(self):
        """
        Rule 2_4: No while inside IRQ
        """
        erro = 0

        irqFuncs = self.createFunctionIrqList()
        for function in irqFuncs:
            for token in self.cfg.tokenlist:
                scope = self.getScope(token)
                if scope.function.Id == function.Id:
                    if token.str in ["while", "for", "do"]:
                        isrName = function.token.str
                        self.printRuleViolation(
                            "2_4", f"Use of {fg.blue}{token.str}{fg.rs} inside {fg.blue}{isrName}{fg.rs}", RULE_2_4_ERRO_TXT
                        )
                        erro = erro + 1
        return erro

    def rule_3_1(self):
        """
        no include guard in .h file
        """
        erro = 0

        fname = self.cfg.tokenlist[0].file
        if not is_header(fname):
            return erro

        # TODO do with regex?
        fname = os.path.basename(self.cfg.tokenlist[0].file)
        fnameX = fname.replace("-", "_")
        fnameX = fnameX.replace(".", "_")
        h0 = f"#ifndef {fnameX}"
        h1 = f"#define {fnameX}"
        hl = f"#endif"

        allDirectives = self.cfg.directives
        headerDirectives = []
        for d in allDirectives:
            if d.file.find(fname) > 0:
                headerDirectives.append(d)

        # easy, no directives
        if len(headerDirectives) == 0:
            erro = 1
        if len(headerDirectives) < 3:
            erro = 1
        else:
            if headerDirectives[0].str.lower().find(h0):
                erro = 1
            if headerDirectives[1].str.lower().find(h1):
                erro = 1
            if headerDirectives[-1].str.lower().find(hl):
                erro = 1

        if erro:
            self.printRuleViolation(
                "3_1", f"no include guard detected in file {fg.blue}{fname}{fg.rs}", RULE_3_1_ERRO_TXT
            )

        return erro

    def rule_3_2(self):
        """
        No C code in .h file
        """
        erro = 0

        headList = []
        for token in self.cfg.tokenlist:
            if is_header(token.file):
                if token.isOp:
                    if token.file in headList:
                        continue

                    # pointer declaration
                    if token.astOperand1 == None:
                        continue

                    # skip prototype
                    if token.astOperand1.variable == None:
                        continue

                    fileName = os.path.basename(token.file)

                    self.printRuleViolation(
                        "3_2",
                        f"Use of C code declaration in {fg.blue}line {token.linenr}{fg.rs} inside file {fg.blue}{fileName}{fg.rs}",
                        RULE_3_2_ERRO_TXT,
                    )
                    headList.append(token.file)
                    erro = erro + 1
        return erro


def main():
    parser = argparse.ArgumentParser(description="Process some dump c file")
    parser.add_argument(
        "check_path", help="check path with dump file created by cppcheck"
    )
    parser.add_argument(
        "--output-file",
        type=argparse.FileType("w"),
        help="csv file name to save result",
    )
    parser.add_argument(
        "--print-table",
        action=argparse.BooleanOptionalAction,
        help="print table with report",
    )
    args = parser.parse_args()

    file = args.check_path
    if os.path.isdir(file):
        files = [y for x in os.walk(file) for y in glob(os.path.join(x[0], "*.dump"))]
    else:
        files = [file]

    erroTotal = 0
    erroLog = []

    for f in files:
        print("--------------")
        print(f)
        checkName = os.path.relpath(f, file).split("/")[0]
        print(f"Checking: {checkName}")

        data = cppcheckdata.CppcheckData(f)
        check = EmbeddedC(data, checkName, f)
        for cfg in data.iterconfigurations():
            check.updateCfg(cfg)
            check.getOnlyGlobalVars()
            check.getAllVarAssigments()
            check.rule_1_1()
            check.rule_1_2()
            check.rule_1_3()
            check.rule_2_1()
            check.rule_2_2()
            check.rule_2_3()
            check.rule_2_4()
            check.rule_3_1()
            check.rule_3_2()
        erroTotal = erroTotal + check.erroTotal
        erroLog.append(check.erroLog)

    table = []
    for erro in erroLog:
        for e in erro:
            table.append(e.values())

    if args.output_file:
        writer = csv.writer(args.output_file)
        writer.writerows(table)
        args.output_file.close()

    if args.print_table:
        print(tabulate(table, headers="firstrow", tablefmt="fancy_grid"))

    sys.exit(erroTotal)

if __name__ == "__main__":
    main()
