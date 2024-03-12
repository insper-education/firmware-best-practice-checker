#!/usr/bin/env python3
import argparse
import csv
import os
import sys
import yaml
from glob import glob
import re

from sty import bg, ef, fg, rs
from tabulate import tabulate

import cppcheckdata
from misra import getArguments, isFunctionCall


class checker:
    def __init__(
        self, data, repo_name, file_path, rtos, rules_yml=None, print_enable=True
    ):
        self.data = data
        self.rtos = rtos
        self.rules_yml = rules_yml
        self.repo_name = repo_name
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.read_config()
        self.erro_total = 0
        self.print_enable = print_enable
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

    def is_header(self, file):
        return file.lower().endswith(".h")

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

            while t.variable is None:
                t = t.astOperand1
                if t is None:
                    return None
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
                if token.previous.str == "gpio_set_irq_enabled_with_callback":
                    func_arg = getArguments(token)[-1]
                    if func_arg.str == "&":
                        # using function pointer a.k &btn_callback
                        func = func_arg.next
                    else:
                        # using only btn_callback
                        func = func_arg

                    if func.function is not None:
                        irq_funcs.append(func.function)

        res = []
        [res.append(x) for x in irq_funcs if x not in res]
        return res

    def create_rtos_task_list(self):
        # TODO improve to get info from task_create
        task_funcs = []
        for func in self.cfg.functions:
            if func.name.find("task") >= 0:
                task_funcs.append(func)

        return task_funcs

    def print_rule_violation(self, ruleN, alias, where, text):
        self.erro_total = self.erro_total + 1
        erro_text = text[0]
        self.erro_log.append(
            {
                "repo": self.repo_name,
                "file": self.file_name,
                "rule": ruleN,
                "alias": alias,
                "file": where,
                "text": erro_text,
            }
        )
        if self.print_enable:
            print(f" - [RULE {ruleN} {alias} VIOLATION] {where} \r\n\t {erro_text}")

    def print_log_xml(self):
        xml_header = '<?xml version="1.0" encoding="UTF-8"?>\n<results version="2">\n    <code-quality version="1"/>\n    <errors>'
        xml_footer = "    </errors>\n</results>"

        xml_errors = ""
        for error in self.erro_log:
            xml_error = f"""
        <error id="{error['alias']}" severity="style" msg="{error['text']}">
            <location file="{error['file']}"/>
        </error>"""
            xml_errors += xml_error

        xml_full = f"{xml_header}{xml_errors}\n{xml_footer}"
        print(xml_full, file=sys.stderr)

    def rule_1_1(self):
        """
        Rule 1_1: All global variables assigment in IRQ or Callback should be volatile
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
                    "notVolatileVarIrq",
                    f"variable {var_name} in function {func_name}",
                    self.config["RULE_1_1_ERRO_TXT"],
                )
                var_erro_list_id.append(ass["variable"].Id)
                erro = erro + 1
        return erro

    def rule_1_2(self):
        """
        Rule 1_2: Do not use volatile in local var
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
                    "badUseofVolatile",
                    f"variable {var_name} in function {func_name}",
                    self.config["RULE_1_2_ERRO_TXT"],
                )
                erro = erro + 1
        return erro

    def rule_1_3(self):
        """
        Rule 1_3: only use global vars in IRQ
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
                "badUseGlobalVar",
                f"global variable {var_name}",
                self.config["RULE_1_3_ERRO_TXT"],
            )
            var_erro_list_id.append(ass["variable"].Id)
            erro = erro + 1

        return erro

    def rule_3_x(self, rule_n, alias, erro_txt, rule):
        """
        Rule 3: search for forbiten functions call inside ISR
        """
        erro = 0
        irq_funcs = self.create_function_irq_list()
        for function in irq_funcs:
            tokens = []
            for token in self.cfg.tokenlist:
                scope = self.get_scope(token)
                if scope.function.Id == function.Id:
                    tokens.append(token)

                    if token.functionId is not None:
                        extra_tokens = self.get_tokens_function_call(token.functionId)
                        tokens.extend(extra_tokens)

            for token in tokens:
                res = [ele for ele in rule if (ele in token.str)]
                if res:
                    irq_name = function.token.str
                    call_name = token.str
                    self.print_rule_violation(
                        rule_n,
                        alias,
                        f"function call to {call_name} inside {irq_name}",
                        erro_txt,
                    )
                    erro = erro + 1
        return erro

    def rule_3_1(self):
        """
        Rule 2_1: No delay inside IRQ
        """
        return self.rule_3_x(
            "3_1",
            "delayInIRQ",
            self.config["RULE_3_1_ERRO_TXT"],
            self.config["DELAY_FUNCTIONS"],
        )

    def rule_3_2(self):
        """
        Rule 2_2: No oled calls inside IRQ
        """
        return self.rule_3_x(
            "3_2",
            "oledInIRQ",
            self.config["RULE_3_2_ERRO_TXT"],
            self.config["OLED_FUNCTIONS"],
        )

    def rule_3_3(self):
        """
        Rule 2_3: No printf calls inside IRQ
        """
        return self.rule_3_x(
            "3_3",
            "printfInIRQ",
            self.config["RULE_3_3_ERRO_TXT"],
            self.config["PRINTF_FUNCTIONS"],
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
                            "whileInIRQ",
                            f"Use of {token.str} inside {irq_name}",
                            self.config["RULE_3_4_ERRO_TXT"],
                        )
                        erro = erro + 1
        return erro

    def rule_4_1(self):
        """
        Use fromISR in interruptions
        """
        erro = 0
        irq_funcs = self.create_function_irq_list()
        for function in irq_funcs:
            for token in self.cfg.tokenlist:
                scope = self.get_scope(token)
                if scope.function.Id == function.Id:
                    if token.str in ["xQueueSend", "xSemaphoreGive"]:
                        if token.str.find("FromISR") < 0:
                            irq_name = function.token.str
                            self.print_rule_violation(
                                "4_1",
                                "rtosMissingFromISR",
                                f"Use of {token.str} inside {irq_name}",
                                self.config["RULE_4_1_ERRO_TXT"],
                            )
                            erro = erro + 1
        return erro

    def rule_4_2(self):
        """
        Do not use fromISR in tasks
        """
        erro = 0
        task_funcs = self.create_rtos_task_list()
        for function in task_funcs:
            for token in self.cfg.tokenlist:
                scope = self.get_scope(token)
                if scope.function.Id == function.Id:
                    if token.str.find("FromISR") >= 0:
                        irq_name = function.token.str
                        self.print_rule_violation(
                            "4_2",
                            "rtosBadUseOfFromISR",
                            f"Use of {token.str} inside {irq_name}",
                            self.config["RULE_4_2_ERRO_TXT"],
                        )
                        erro = erro + 1
        return erro

    def get_tokens_function_call(self, functionId):
        tokens = []
        for token in self.cfg.tokenlist:
            scope = self.get_scope(token)
            if scope.function.Id == functionId:
                tokens.append(token)
        return tokens

    def rule_4_3(self):
        """
        Do not use time delay in tasks
        """
        erro = 0
        task_funcs = self.create_rtos_task_list()
        for function in task_funcs:
            tokens = []
            for token in self.cfg.tokenlist:
                scope = self.get_scope(token)
                if scope.function.Id == function.Id:
                    tokens.append(token)
                    if token.functionId is not None:
                        extra_tokens = self.get_tokens_function_call(token.functionId)
                        tokens.extend(extra_tokens)

            for token in tokens:
                if any(x in token.str for x in self.config["DELAY_FUNCTIONS"]):
                    task_name = function.token.str
                    self.print_rule_violation(
                        "4_3",
                        "rtosBadUseOfDelay",
                        f"Use of {token.str} inside {task_name}",
                        self.config["RULE_4_3_ERRO_TXT"],
                    )
                    erro = erro + 1
        return erro

    def rule_4_4(self):
        """
        Rule 4_4: Do not use global vars with RTOS! Youdont need them.
        """
        erro = 0

        var_erro_list = []

        # interact in global vars only assigments
        for var in self.get_only_golbal_var_ass():
            var_name = var["variable"].nameToken.str
            var_type = var["variable"].typeStartToken.str

            if var_name in var_erro_list:
                continue

            if var_type in self.config["RULE_1_3_EXCEPTIONS"]:
                continue

            self.print_rule_violation(
                "4_4",
                "rtosBadUseGlobalVar",
                f"global variable {var_name}",
                self.config["RULE_4_4_ERRO_TXT"],
            )
            erro = erro + 1

            var_erro_list.append(var_name)
        return erro

    def canonical_form(self, s: str) -> str:
        """Convert a string to its canonical form."""
        # Remove any file extensions
        s = re.sub(r"\.\w+$", "", s)

        # Convert camelCase to snake_case
        s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)

        # Convert everything to lowercase
        s = s.lower()

        # Remove trailing underscores
        s = s.rstrip("_")

    def is_variation(self, base: str, candidate: str) -> bool:
        """Check if the candidate string is a variation of the base string."""
        return self.canonical_form(base) != self.canonical_form(candidate)

    def rule_2_1(self):
        """
        no include guard in .h file
        """
        erro = 0

        h_list = []
        for directives in self.cfg.directives:
            file_name = os.path.basename(directives.file)
            if self.is_header(file_name) and file_name not in h_list:
                h_list.append(file_name)

        for fname in h_list:
            header_directives = []
            for d in self.cfg.directives:
                if os.path.basename(d.file.lower()) == fname.lower():
                    header_directives.append(d)

            # easy, no directives
            if len(header_directives) == 0 or len(header_directives) < 3:
                erro = 1
            else:
                h0 = header_directives[0].str.lower().split("#ifndef")[-1].strip()
                h1 = header_directives[1].str.lower().split("#define")[-1].strip()
                hl = header_directives[-1].str.lower().find("#endif")

                if (
                    self.is_variation(h0, fname)
                    or self.is_variation(h1, fname)
                    or hl < 0
                ):
                    erro = 1

            if erro:
                self.print_rule_violation(
                    "2_1",
                    "noIncludeGuard",
                    f"no include guard detected in file or wrong implementation on: {fname}",
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
            if self.is_header(token.file):
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
                        "cInHeadFile",
                        f"Use of C code declaration in line {token.linenr} inside file {file_name}",
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
        "--rtos",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="rtos specific config",
    )
    parser.add_argument(
        "--xml",
        action=argparse.BooleanOptionalAction,
        help="print xml",
    )
    parser.add_argument(
        "--disable",
        action='append',
        default= "",
        type=str,
        help='disable rule by id: exemple --disable rule_1_1'
    )
    args = parser.parse_args()

    file = args.check_path
    if os.path.isdir(file):
        files = [y for x in os.walk(file) for y in glob(os.path.join(x[0], "*.dump"))]
    else:
        files = [file]

    rtos = args.rtos
    disable = args.disable

    erro_total = 0
    erro_log = []

    for f in files:
        print("--------------")
        print(f)
        check_name = os.path.relpath(f, file).split("/")[0]
        print(f"Checking: {check_name}")
        data = cppcheckdata.CppcheckData(f)
        check = checker(data, check_name, f, rtos=args.rtos, print_enable=not args.xml)
        for cfg in data.iterconfigurations():
            if cfg.name != "":
                continue
            check.update_cfg(cfg)
            check.get_only_global_vars()
            check.get_all_var_ass()

            if 'rule_1_1' not in disable:
                check.rule_1_1()
            if 'rule_1_2' not in disable:
                check.rule_1_2()
            if rtos is False and 'rule_1_3' not in disable:
                check.rule_1_3()
            if 'rule_2_1' not in disable:
                check.rule_2_1()
            if 'rule_2_2' not in disable:
                check.rule_2_2()
            if 'rule_3_1' not in disable:
                check.rule_3_1()
            if 'rule_3_2' not in disable:
                check.rule_3_2()
            if 'rule_3_3' not in disable:
                check.rule_3_3()
            if 'rule_3_4' not in disable:
                check.rule_3_4()
            if 'rule_4_1' not in disable:
                check.rule_4_1()
            if 'rule_4_2' not in disable:
                check.rule_4_2()
            if 'rule_4_3' not in disable:
                check.rule_4_3()
            if rtos and 'rule_4_4' not in disable:
                check.rule_4_4()

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

    if args.xml:
        check.print_log_xml()

    sys.exit(erro_total)


if __name__ == "__main__":
    main()
