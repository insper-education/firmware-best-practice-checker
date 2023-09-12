#!/usr/bin/env python3
import argparse
import csv
import os
import sys
import yaml
from glob import glob

from sty import bg, ef, fg, rs
from tabulate import tabulate

import cppcheckdata
from misra import getArguments, is_header, isFunctionCall


class checker:
    def __init__(self, data, repo_name, file_path, rules_yml=None):
        self.data = data
        self.rules_yml = rules_yml
        self.repo_name = repo_name
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.read_config()
        self.erro_total = 0
        self.erro_log = []
        self.cfg = []

    def update_cfg(self, cfg):
        self.cfg = cfg

    def read_config(self):
        rules_yml_default = os.path.join(os.path.dirname(__file__), "rules.yml")
        rules_yml = rules_yml_default if self.rules_yml == None else self.rules_yml
        with open(rules_yml, "r") as stream:
            try:
                self.config = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

    def get_vars(self):
        return self.cfg.variables

    def get_scopes(self):
        return self.cfg.scopes

    def get_previous_scope(self, scope_id):
        cnt = 0
        scopes = self.get_scopes()
        for scope in scopes:
            if scope.Id == scope_id:
                return scopes[cnt - 1]
            cnt = cnt + 1

    def get_only_global_vars(self):
        vars = []
        for var in self.cfg.variables:
            if var.isGlobal:
                vars.append(var)
        return vars

    def get_scope(self, token):
        scope = token.scope
        while scope.type != "Function":
            scope = self.get_previous_scope(scope.Id)
        return scope

    def get_var_ass(self, token):
        var = None
        if token.astOperand1.str == "[":
            t = token.astOperand1
            while t.variable == None:
                t = t.astOperand1
            var = t.variable
        else:
            var = token.astOperand1.variable
        return var

    def get_all_var_ass(self):
        ass = []

        for token in self.cfg.tokenlist:
            if token.isAssignmentOp and token.scope.type != "Global":
                variable = self.get_var_ass(token)
                if variable is None:
                    continue

                scope = self.get_scope(token)
                ass.append(
                    {
                        "className": scope.className,
                        "variable": variable,
                        "line": token.linenr,
                    }
                )
        return ass

    def get_only_golbal_var_ass(self):
        all_var_ass = self.get_all_var_ass()
        global_vars = self.get_only_global_vars()

        # create list of global var assigments
        global_ass = []
        for var in global_vars:
            for ass in all_var_ass:
                if var.Id == ass["variable"].Id:
                    global_ass.append(ass)
        return global_ass

    def is_funq_irq(self, f):
        res = [ele for ele in self.config["IRQ_NAMES"] if (ele in f.name)]
        return True if res else False

    def create_function_irq_list(self):
        irq_funcs = []
        for f in self.cfg.functions:
            if self.is_funq_irq(f):
                if f != None:
                    irq_funcs.append(f)

        # TODO: export this to config file
        for token in self.cfg.tokenlist:
            if isFunctionCall(token):
                if token.previous.str == "pio_handler_set":
                    func = getArguments(token)[-1]
                    if func.function is not None:
                        irq_funcs.append(func.function)

        return irq_funcs

    def print_rule_violation(self, ruleN, where, text):
        self.erro_total = self.erro_total + 1
        erro_text = text[0]
        self.erro_log.append(
            {
                "repo": self.repo_name,
                "file": self.file_name,
                "rule": ruleN,
                "file": where,
                "text": erro_text,
            }
        )
        print(f" - [{fg.red}RULE {ruleN} VIOLATION{fg.rs}] {where} \r\n\t {erro_text}")

    def rule_1_1(self):
        """
        Rule 1: All global variables assigment in IRQ or Callback should be volatile
        """
        erro = 0

        assigments = self.get_only_golbal_var_ass()
        irq_funcs = self.create_function_irq_list()

        # create lisr of function IRQ name
        irq_func_class_names = []
        for func in irq_funcs:
            irq_func_class_names.append(func.name)

        var_erro_list_id = []
        for ass in assigments:
            # excluce specific types exceptions (rtos, lcd)
            var_type = ass["variable"].typeStartToken.str
            if [ele for ele in self.config["RULE_1_1_EXCEPTIONS"] if (ele in var_type)]:
                continue

            # only check for var ass in IRQ functions
            if ass["className"] not in irq_func_class_names:
                continue

            # skip duplicate error
            if ass["variable"].Id in var_erro_list_id:
                continue

            if not ass["variable"].isVolatile:
                var_name = ass["variable"].nameToken.str
                func_name = ass["className"]
                self.print_rule_violation(
                    "1_1",
                    f"variable {fg.blue}{var_name}{fg.rs} in function {fg.blue}{func_name}{fg.rs}",
                    self.config["RULE_1_1_ERRO_TXT"],
                )
                var_erro_list_id.append(ass["variable"].Id)
                erro = erro + 1
        return erro

    def rule_1_2(self):
        """
        Rule 2: Do not use volatile in local var
        """

        erro = 0

        assigments = self.get_all_var_ass()
        irq_funcs = self.create_function_irq_list()

        # create lisr of function IRQ name
        irq_func_class_names = []
        for func in irq_funcs:
            irq_func_class_names.append(func.name)

        for ass in assigments:
            # exclue IRQ functions
            if ass["className"] in irq_func_class_names:
                continue

            if ass["variable"].isVolatile and ass["variable"].isLocal:
                var_name = ass["variable"].nameToken.str
                func_name = ass["className"]
                self.print_rule_violation(
                    "1_2",
                    f"variable {fg.blue}{var_name}{fg.rs} in function {fg.blue}{func_name}{fg.rs}",
                    self.config["RULE_1_2_ERRO_TXT"],
                )
                erro = erro + 1
        return erro

    def rule_1_3(self):
        """
        Rule 2: only use global vars in IRQ
        """
        erro = 0

        assigments = self.get_only_golbal_var_ass()
        irq_funcs = self.create_function_irq_list()

        # create lisr of function IRQ name
        irq_func_class_names = []
        for func in irq_funcs:
            irq_func_class_names.append(func.name)

        # create var list that are update in ISR
        var_ass_irq_ids = []
        for ass in assigments:
            if [ele for ele in irq_func_class_names if (ele in ass["className"])]:
                var_ass_irq_ids.append(ass["variable"].Id)

        # interact in global vars only assigments
        var_erro_list_id = []
        for ass in assigments:
            # excluce specific types exceptions (rtos, lcd)
            if ass["variable"].typeStartToken.str in self.config["RULE_1_3_EXCEPTIONS"]:
                continue

            # exclude var that are accessed in Isr
            if ass["variable"].Id in var_ass_irq_ids:
                continue

            # skip duplicate error
            if ass["variable"].Id in var_erro_list_id:
                continue

            # erro print
            var_name = ass["variable"].nameToken.str
            self.print_rule_violation(
                "1_3",
                f"global variable {fg.blue}{var_name}{fg.rs}",
                self.config["RULE_1_3_ERRO_TXT"],
            )
            var_erro_list_id.append(ass["variable"].Id)
            erro = erro + 1

        return erro

    def rule_3_x(self, rule_n, erro_txt, rule):
        """
        Rule 3: search for forbiten functions call inside ISR
        """
        erro = 0

        irq_funcs = self.create_function_irq_list()
        for function in irq_funcs:
            for token in self.cfg.tokenlist:
                scope = self.get_scope(token)
                if scope.function.Id == function.Id:
                    res = [ele for ele in rule if (ele in token.str)]
                    if res:
                        irq_name = function.token.str
                        call_name = token.str
                        self.print_rule_violation(
                            rule_n,
                            f"function call to {fg.blue}{call_name}{fg.rs} inside {fg.blue}{irq_name}{fg.rs}",
                            erro_txt,
                        )
                        erro = erro + 1
        return erro

    def rule_3_1(self):
        """
        Rule 2_1: No delay inside IRQ
        """
        return self.rule_3_x(
            "3_1", self.config["RULE_3_1_ERRO_TXT"], self.config["DELAY_FUNCTIONS"]
        )

    def rule_3_2(self):
        """
        Rule 2_2: No oled calls inside IRQ
        """
        return self.rule_3_x(
            "3_2", self.config["RULE_3_2_ERRO_TXT"], self.config["OLED_FUNCTIONS"]
        )

    def rule_3_3(self):
        """
        Rule 2_3: No printf calls inside IRQ
        """
        return self.rule_3_x(
            "3_3", self.config["RULE_3_3_ERRO_TXT"], self.config["PRINTF_FUNCTIONS"]
        )

    def rule_3_4(self):
        """
        Rule 2_4: No while inside IRQ
        """
        erro = 0

        irq_funcs = self.create_function_irq_list()
        for function in irq_funcs:
            for token in self.cfg.tokenlist:
                scope = self.get_scope(token)
                if scope.function.Id == function.Id:
                    if token.str in ["while", "for", "do"]:
                        irq_name = function.token.str
                        self.print_rule_violation(
                            "3_4",
                            f"Use of {fg.blue}{token.str}{fg.rs} inside {fg.blue}{irq_name}{fg.rs}",
                            self.config["RULE_3_4_ERRO_TXT"],
                        )
                        erro = erro + 1
        return erro

    def rule_2_1(self):
        """
        no include guard in .h file
        """
        erro = 0

        fname = self.cfg.tokenlist[0].file

        if not is_header(fname):
            return erro

        # TODO do with regex?
        fname = os.path.basename(self.cfg.tokenlist[0].file)
        fnameX = fname.replace("-", "_").lower()
        fnameX = fnameX.replace(".", "_").lower()
        h0 = f"#ifndef {fnameX}"
        h1 = f"#define {fnameX}"
        hl = f"#endif"

        all_directives = self.cfg.directives
        header_directives = []
        for d in all_directives:
            if os.path.basename(d.file.lower()) == fname.lower():
                header_directives.append(d)

        # easy, no directives
        if len(header_directives) == 0:
            erro = 1
        if len(header_directives) < 3:
            erro = 1
        else:
            if header_directives[0].str.lower().find(h0):
                erro = 1
            if header_directives[1].str.lower().find(h1):
                erro = 1
            if header_directives[-1].str.lower().find(hl):
                erro = 1

        if erro:
            self.print_rule_violation(
                "2_1",
                f"no include guard detected in file or wrong implementation on: {fg.blue}{fname}{fg.rs}",
                self.config["RULE_2_1_ERRO_TXT"],
            )

        return erro

    def rule_2_2(self):
        """
        No C code in .h file
        """
        erro = 0

        head_list = []
        for token in self.cfg.tokenlist:
            if is_header(token.file):
                if token.isOp:
                    if token.file in head_list:
                        continue

                    # pointer declaration
                    if token.astOperand1 is None:
                        continue

                    # skip prototype
                    if token.astOperand1.variable is None:
                        continue

                    file_name = os.path.basename(token.file)

                    self.print_rule_violation(
                        "2_2",
                        f"Use of C code declaration in {fg.blue}line {token.linenr}{fg.rs} inside file {fg.blue}{file_name}{fg.rs}",
                        self.config["RULE_2_2_ERRO_TXT"],
                    )
                    head_list.append(token.file)
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

    erro_total = 0
    erro_log = []

    for f in files:
        print("--------------")
        print(f)
        check_name = os.path.relpath(f, file).split("/")[0]
        print(f"Checking: {check_name}")

        data = cppcheckdata.CppcheckData(f)
        check = checker(data, check_name, f)
        for cfg in data.iterconfigurations():
            check.update_cfg(cfg)
            check.get_only_global_vars()
            check.get_all_var_ass()
            check.rule_1_1()
            check.rule_1_2()
            check.rule_1_3()
            check.rule_2_1()
            check.rule_2_2()
            check.rule_3_1()
            check.rule_3_2()
            check.rule_3_3()
            check.rule_3_4()
        erro_total = erro_total + check.erro_total
        erro_log.append(check.erro_log)

    table = []
    for erro in erro_log:
        for e in erro:
            table.append(e.values())

    if args.output_file:
        writer = csv.writer(args.output_file)
        writer.writerows(table)
        args.output_file.close()

    if args.print_table:
        print(tabulate(table, headers="firstrow", tablefmt="fancy_grid"))

    sys.exit(erro_total)


if __name__ == "__main__":
    main()
