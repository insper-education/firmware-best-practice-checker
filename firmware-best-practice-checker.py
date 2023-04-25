#!/usr/bin/env python3
import argparse
import csv
import os
import sys
from glob import glob

from tabulate import tabulate

import cppcheckdata
from misra import (get_type_conversion_to_from, getArguments, is_header,
                   isFunctionCall, isKeyword)

IRQ_NAMES = ['callback', 'Handler']
DELAY_FUNCTIONS = ['delay_', 'delay_ms', 'delay_us', 'delay_s']
OLED_FUNCTIONS = ['gfx_mono_']
PRINTF_FUNCTIONS = ['printf', 'sprintf']

RULE_1_3_EXCEPTIONS = ['lv_', 'SemaphoreHandle_t', 'TimerHandle_t', 'QueueHandle_t']
RULE_1_1_ERRO_TXT = ["All global variables that are accessed from IRQ must be declared as volatile to ensure that the compailer will not optimize it out.",
                   "All global variables that are updated in IRQ or Callback should be volatile"]
RULE_1_2_ERRO_TXT = ["Local variables should not be declared as volatile to ensure that the compailer will optimize it out.",
                   "Local variables should NOT be volatile"]
RULE_1_3_ERRO_TXT = ["Global variables should generally be avoided, except when necessary or when dealing with IRQs",
                   "Do not use global vars outside IRQ"]

RULE_2_1_ERRO_TXT = ['ISR shall be fast as possible, forbidden use of delay functions inside hardware interruption',
                     'Forbidden use of delay functions within IRQ']
RULE_2_2_ERRO_TXT = ['ISR shall be fast as possible, forbidden OLED update inside hardware interruption',
                     'Forbidden use of gfx_mono_... functions within IRQ']
RULE_2_3_ERRO_TXT = ['ISR shall be fast as possible, forbidden PRINTF/SPRINTF inside hardware interruption',
                     'Forbidden use of printf/sprintf functions within IRQ']
RULE_2_4_ERRO_TXT = ['ISR shall be fast as possible avoid the use of while and for loops',
                     'Forbidden use of loops/While within IRQ']

RULE_3_1_ERRO_TXT = ['Header file (.h) contents should be protected against multiple inclusions (include guard)',
                     'Header file contents should be protected against multiple inclusions (include guard)']
RULE_3_2_ERRO_TXT = ['Do not implement code inside .h file',
                     'Forbidden implementation of C code in .h file']


class EmbeddedC():
    def __init__(self, data, repoName):

        self.data = data
        self.repoName = repoName
        self.cfg = []
        self.funcList = []
        self.funcIrqList = []
        self.varList = []
        self.erroShortText = False
        self.errorCnt = {'1_1':0, '1_2':0, '1_3': 0,
                         '2_1': 0, '2_2':0, '2_3':0, '2_4':0,
                         '3_1':0, '3_2':0}
        self.erro = []
        self.init()

    def init(self):
        for cfg in self.data.iterconfigurations():
            self.updateCfg(cfg)
            self.createFuncList()
            self.createFunctionIrqList()
            self.createVarList()

    def updateCfg(self, cfg):
        self.cfg = cfg

    def print(self):
        print('---')
        for var in self.varList:
            print(var)
        print('´----------------------')
        for fun in self.funcList:
            print(fun)

    def isFunctionIRQ(self, f):
        fName = f['name']
        res = [ele for ele in IRQ_NAMES if(ele in fName)]
        return True if res else False

    def searchFuncByScopeId(self, id):
        for f in self.funcList:
            if id == f['scopeId']:
                return f
        return None

    def searchVarName(self, name):
        for v in self.varList:
            if name == v['name']:
                return v
        return None

    def getGlobalVarAssigments(self):
        l = []
        for token in self.cfg.tokenlist:
            if token.isAssignmentOp:
                f = self.searchFuncByScopeId(token.scope.Id)
                if f is not None:
                    var = self.searchVarName(token.astOperand1.str)
                    if var is not None and var['isGlobal'] == True:
                        l.append(
                            {
                                'func': f,
                                'var': var,
                            }

                        )
        return l

    def getAllVarAssigments(self):
        l = []
        for token in self.cfg.tokenlist:
            if token.isAssignmentOp:
                f = self.searchFuncByScopeId(token.scope.Id)
                if f is not None:
                    var = self.searchVarName(token.astOperand1.str)
                    if var is not None:
                        l.append(
                            {
                                'func': f,
                                'var': var,
                            }

                        )
        return l

    def getIRQVarAssigments(self):
        l = []
        irqFunctionsId = [ sub['functionId'] for sub in self.funcIrqList ]
        assigmentVars = self.getAllVarAssigments()
        for var in assigmentVars:
            if var['func']['functionId'] in irqFunctionsId:
                l.append(var)
        return l

    def getNoIRQVarAssigments(self):
        l = []
        irqFunctionsId = [ sub['functionId'] for sub in self.funcIrqList ]
        assigmentVars = self.getAllVarAssigments()
        for var in assigmentVars:
            if var['func']['functionId'] not in irqFunctionsId:
                l.append(var)
        return l

    def createVarList(self):
        for var in self.cfg.variables:
            # TODO investigate bug in .dump?
            #if var.nameTokenId== '0':
            #    continue
            if var.nameToken:
                self.varList.append(
                    {
                    "id": var.Id,
                    "name": var.nameToken.str,
                    "type": var.typeStartToken.str,
                    "isGlobal": var.isGlobal,
                    "isLocal": var.isLocal,
                    "isArgument": var.isArgument,
                    "isConstant": var.isConst,
                    "isVolatile": var.isVolatile,
                    }
                )

    def createFuncList(self):
        for scope in self.cfg.scopes:
            if scope.type == "Function":
                self.funcList.append(
                    {
                    'scopeId': scope.Id,
                    'functionId': scope.function.Id,
                    'name': scope.function.name,
                    'argId': scope.function.argumentId
                    }
                )

    def createFunctionIrqList(self):
        irqList = []
        for f in self.funcList:
            if self.isFunctionIRQ(f):
                irqList.append(f)

        for token in self.cfg.tokenlist:
            if isFunctionCall(token):
                if token.previous.str == 'pio_handler_set':
                    fcallback = getArguments(token)[-1]
                    irqList.append({
                        'name': fcallback.str,
                        'scopeId': fcallback.scopeId,
                        'functionId': fcallback.functionId
                    })
        self.funcIrqList = irqList

    def erroShort(self):
        self.erroShortText = True

    def printRuleViolation(self, ruleN, where, text):
        erroText = text[0] if self.erroShortText is False else text[1]
        print (f' - [RULE {ruleN} VIOLATION] {where} \r\n\t {erroText}')
        self.erro.append({
            'repo': self.repoName,
            'rule': ruleN,
            'file': where,
            'text': erroText,
        })

    def rule_1_1(self):
        """
        Rule 1: All global variables assigment in IRQ or Callback should be volatile
        """
        assigmentList = self.getIRQVarAssigments()
        erro = 0
        for ass in assigmentList:
            if ass['var']['isVolatile'] != True:
                varName = ass['var']['name']
                funcName = ass['func']['name']
                self.printRuleViolation("1_1", f'[variable {varName} in function {funcName}]', RULE_1_1_ERRO_TXT)
                erro = erro + 1
        self.errorCnt['1_1'] = erro
        return erro

    def rule_1_2(self):
        erro = 0
        local = self.getNoIRQVarAssigments()
        for l in local:
            if l['var']['isVolatile'] and l['var']['isLocal']:
                varName = l['var']['name']
                funcName = l['func']['name']
                self.printRuleViolation("1_2", f'[variable {varName} in function {funcName}]', RULE_1_2_ERRO_TXT)
                erro = erro + 1
        self.errorCnt['1_2'] = erro
        return erro

    def rule_1_3(self):
        """
        Rule 2: only use global vars in IRQ
        """
        varList = self.getGlobalVarAssigments()
        erro = 0
        for l in varList:
            # skip global exceptions (rtos, lcd)
            if [ele for ele in RULE_1_3_EXCEPTIONS if(ele in l['var']['type'])]:
                continue

            # exclude var that are accessed in IRQ
            if self.isFunctionIRQ(l['func']) is False:
                varName = l['var']['name']
                funcName = l['func']['name']
                self.printRuleViolation("1_3", f'[variable {varName} in function {funcName}]', RULE_1_3_ERRO_TXT)
                erro = erro + 1
        self.errorCnt['1_3'] = erro
        return erro

    def rule_2_x(self, ruleN, ruleTxt, rule):
        """
        Rule 3: search for forbiten functions call inside ISR
        """
        erro = 0
        for f in self.funcIrqList:
            for token in self.cfg.tokenlist:
                if token.scope.Id == f['scopeId']:
                    res = [ele for ele in rule if(ele in token.str)]
                    if res:
                        isrName = f['name']
                        callName = token.str
                        self.printRuleViolation(ruleN, f"call to {callName} inside {isrName}", ruleTxt)
                        erro = erro + 1
        self.errorCnt[ruleN] = erro
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
        for f in self.funcIrqList:
            for token in self.cfg.tokenlist:
                if token.scope.Id == f['scopeId']:
                    if token.str == 'while':
                        isrName = f['name']
                        self.printRuleViolation("2_4", f"use of 'while' inside {isrName}", RULE_2_4_ERRO_TXT)
                        erro = erro + 1

        self.errorCnt["2_4"] = erro
        return erro

    # TODO
    def rule_2_5(self):
        """
        rule 4: search complex code in ISR
        """
        fIrqList = []
        for f in self.funcList:
            if self.isFunctionIRQ(f):
                fIrqList.append(f)

        # number of functions call
        for f in fIrqList:
            print(f['name'])
            fCallCnt = 0
            for token in self.cfg.tokenlist:
                if token.scope.Id == f['scopeId']:
                    if isFunctionCall(token):
                        fCallCnt = fCallCnt + 1
            print(fCallCnt)

    def rule_3_1(self):
        """
        no include guard in .h file
        """
        erro = 0

        fname = self.cfg.tokenlist[0].file
        if not is_header(fname):
            return erro

        # TODO do with regex
        fname = os.path.basename(self.cfg.tokenlist[0].file)
        fnameX = fname.replace('-', '_')
        fnameX = fnameX.replace('.', '_')
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
            self.printRuleViolation("3_1", f"include guard in file {fname}", RULE_3_1_ERRO_TXT)
            self.errorCnt['3_1'] = self.errorCnt['3_1'] + erro

        return erro

    # TODO DOING
    def rule_3_2(self):
        """
        No C code in .h file
        """
        erro = 0
        for token in self.cfg.tokenlist:
            if is_header(token.file):
                if get_type_conversion_to_from(token):
                    self.printRuleViolation("3_3", f"Use of C code declaration in line {token.linenr} inside file {token.file}", RULE_3_2_ERRO_TXT)
                    erro = erro + 1


        self.errorCnt['3_2'] = self.errorCnt['3_2'] + erro
        return erro

def main():
    parser = argparse.ArgumentParser(description='Process some dump c file')
    parser.add_argument('dump_file', help='c dump file created by cppcheck')
    args = parser.parse_args()

    file = args.dump_file
    if os.path.isdir(file):
        files = [y for x in os.walk(file) for y in glob(os.path.join(x[0], '*.dump'))]
    else:
        files = [file]

    errorCnt = {'1_1':0, '1_2':0, '1_3': 0,
                '2_1': 0, '2_2':0, '2_3':0, '2_4':0,
                '3_1': 0, '3_2': 0}

    errors = []

    for f in files:
        print('--------------')
        repoName = os.path.relpath(f, file).split('/')[0]
        print(repoName)

        data = cppcheckdata.CppcheckData(f)
        check = EmbeddedC(data, repoName)
        e = []
        for cfg in data.iterconfigurations():
            check.updateCfg(cfg)
            #check.print()
            check.erroShort()
            check.rule_1_1() # global var ISR volatile
            check.rule_1_2() # local var ISR volatile
            check.rule_1_3() # only use global vars in IRQ
            check.rule_2_1() # ISR SAP no delayy
            check.rule_2_2() # ISR SAP no oled
            check.rule_2_3() # ISR SAP no printf
            check.rule_2_4() # ISR SAP no while
            check.rule_3_1() # no include guard
            check.rule_3_2() # C code not allow in head file
            #print('- [RESUME VIOLATIONS]')
            #print(f"\t {check.errorCnt}")
            for key, value in check.errorCnt.items():
                errorCnt[key] = errorCnt[key] + value

        errors.append(check.erro)

    table = []
    for repos in errors:
        for e in repos:
            table.append(e.values())

    with open('studentsq.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(table)

    print(tabulate(table,  headers='firstrow', tablefmt='fancy_grid'))

#    print(errorCnt)
if __name__ == '__main__':
    main()
    sys.exit(cppcheckdata.EXIT_CODE)
