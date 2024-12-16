import os
import ast
import zlib
import base64
import string
import random
import argparse
import sys

class PyObfuscator:
    def __init__(self, code: str, include_imports: bool = False, recursion: int = 1) -> None:
        self._code = code
        self._imports = []
        self._valid_identifiers = [chr(i) for i in range(256, 0x24976) if chr(i).isidentifier()]

        # Options
        self.__include_imports = include_imports
        if recursion < 1:
            raise ValueError("Recursion length cannot be less than 1")
        else:
            self.__recursion = recursion

    def obfuscate(self) -> str:
        self._remove_comments_and_docstrings()
        self._save_imports()

        for _ in range(self.__recursion):
            self._layer_1()
            self._layer_2()
            self._layer_3()  # Add layer 3 obfuscation

        if self.__include_imports:
            self._prepend_imports()
        return self._code

    def _remove_comments_and_docstrings(self) -> None:
        tree = ast.parse(self._code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                    node.body[0] = ast.Pass()
        self._code = ast.unparse(tree)

    def _save_imports(self) -> None:
        def visit_node(node):
            if isinstance(node, ast.Import):
                for name in node.names:
                    self._imports.append((None, name.name))
            elif isinstance(node, ast.ImportFrom):
                module = node.module
                for name in node.names:
                    self._imports.append((module, name.name))

            for child_node in ast.iter_child_nodes(node):
                visit_node(child_node)

        tree = ast.parse(self._code)
        visit_node(tree)
        self._imports.sort(reverse=True, key=lambda x: len(x[1]) + (len(x[0]) if x[0] else 0))

    def _prepend_imports(self) -> None:
        for module, submodule in self._imports:
            if module is not None:
                statement = f"from {module} import {submodule}\n"
            else:
                statement = f"import {submodule}\n"
            self._code = statement + self._code

    def _layer_1(self) -> None:
        layer_template = r"""
{v1} = "{part1}"
{v2} = "{part2}"
{v3} = "{part3}"
{v4} = "{part4}"
exec(__import__("zlib").decompress(__import__("base64").b64decode({v1} + {v2} + {v3} + {v4})))
"""

        compressed = zlib.compress(self._code.encode())
        encoded = base64.b64encode(compressed).decode()

        # Divide the encoded string into 4 parts
        part_length = len(encoded) // 4
        parts = [encoded[i * part_length: (i + 1) * part_length] for i in range(3)]
        parts.append(encoded[3 * part_length:])  # Add the remaining part to the last

        variable_names = [self._generate_random_name() for _ in range(4)]
        formatted_layer = layer_template.format(
            v1=variable_names[0],
            v2=variable_names[1],
            v3=variable_names[2],
            v4=variable_names[3],
            part1=parts[0],
            part2=parts[1],
            part3=parts[2],
            part4=parts[3]
        )

        self._code = formatted_layer
        self._insert_dummy_comments()

    def _layer_2(self) -> None:
        layer = r"""
encrypted = []
for i in range(1, 100):
    if encrypted[in_loc] ^ i == encrypted[re_loc]:
        exec(__import__("zlib").decompress(bytes(map(lambda x: x ^ i, encrypted[:in_loc] + encrypted[in_loc+1:re_loc] + encrypted[re_loc+1:]))))
        break
"""
        key = random.randint(1, 100)
        in_byte = random.randbytes(1)
        re_byte = in_byte[0] ^ key

        encrypted = list(map(lambda x: key ^ x, zlib.compress(self._code.encode())))

        in_loc = random.randint(0, int(len(encrypted)/2))
        re_loc = random.randint(in_loc, len(encrypted) - 1)
        encrypted.insert(in_loc, in_byte[0])
        encrypted.insert(re_loc, re_byte)
        layer = layer.replace("in_loc", str(in_loc)).replace("re_loc", str(re_loc))

        tree = ast.parse(layer)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "encrypted":
                node.id = 'encrypted'
            elif isinstance(node, ast.List):
                node.elts = [ast.Constant(value=x) for x in encrypted]

        self._code = ast.unparse(tree)
        self._insert_dummy_comments()

    def _layer_3(self) -> None:
        layer = r"""
ip_table = []
data = list([int(x) for item in [value.split(".") for value in ip_table] for x in item])
exec(compile(__import__("zlib").decompress(__import__("base64").b64decode(bytes(data))), "<(*3*)>", "exec"))
"""
        def bytes2ip(data: bytes) -> list:
            ip_addresses = []
            for index in range(0, len(data), 4):
                ip_bytes = data[index:index+4]
                ip_bytes += b'\x00' * (4 - len(ip_bytes))  # Remplir si besoin
                ip_addresses.append(".".join(map(str, ip_bytes)))
            return ip_addresses

        # Compression et encodage
        compressed = zlib.compress(self._code.encode())
        encoded = base64.b64encode(compressed)
        ip_addresses = bytes2ip(encoded)

        # Remplacement des IPs dans le code
        tree = ast.parse(layer)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
                node.value.elts = [ast.Constant(value=ip) for ip in ip_addresses]

        try:
            ast.fix_missing_locations(tree)
            self._code = ast.unparse(tree)
        except RecursionError as e:
            print(f"Erreur dans l'AST pour la couche 3 : {e}")
            raise

        self._insert_dummy_comments()

    def _generate_random_name(self) -> str:
        return ''.join(random.choices(string.ascii_letters, k=random.randint(5, 20)))

    def _obfuscate_vars(self) -> None:
        class Transformer(ast.NodeTransformer):
            def __init__(self, outer: PyObfuscator) -> None:
                self._outer = outer

            def rename(self, name: str) -> str:
                if name not in dir(__builtins__) and not name in [x[1] for x in self._outer._imports]:
                    return self._outer._generate_random_name()
                return name

            def visit_Name(self, node: ast.Name) -> ast.Name:
                if node.id in dir(__builtins__) or node.id in [x[1] for x in self._outer._imports]:
                    node = ast.Call(
                        func=ast.Call(
                            func=ast.Name(id="getattr", ctx=ast.Load()),
                            args=[ast.Call(
                                func=ast.Name(id="__import__", ctx=ast.Load()),
                                args=[ast.Constant(value="builtins")],
                                keywords=[]
                            ),
                            ast.Constant(value="eval")],
                            keywords=[]
                        ),
                        args=[ast.Call(
                            func=ast.Name(id="bytes", ctx=ast.Load()),
                            args=[ast.Subscript(
                                value=ast.List(
                                    elts=[ast.Constant(value=x) for x in list(node.id.encode())[::-1]],
                                    ctx=ast.Load()
                                ),
                                slice=ast.Slice(lower=None, upper=None, step=ast.Constant(value=-1))
                            )],
                            keywords=[]
                        )],
                        keywords=[]
                    )
                else:
                    node.id = self.rename(node.id)
                return self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
                node.name = self.rename(node.name)
                return self.generic_visit(node)

            def visit_arg(self, node: ast.arg) -> ast.arg:
                node.arg = self.rename(node.arg)
                return node

            def visit_Constant(self, node: ast.Constant) -> ast.Constant:
                if isinstance(node.value, int):
                    choice = random.randint(1, 2)
                    if choice == 1:
                        num = random.randint(2 ** 16, sys.maxsize)
                        left = node.value * num
                        right = node.value * (num - 1)
                        node = ast.BinOp(left=ast.Constant(value=left), op=ast.Sub(), right=ast.Constant(value=right))
                    else:
                        num = random.randint(2 ** 16, sys.maxsize)
                        times = random.randint(50, 500)
                        node.value = times
                        node = ast.BinOp(left=ast.Constant(value=node.value), op=ast.Mult(), right=ast.Constant(value=num))
                return node

            def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
                node = ast.Call(
                    func=ast.Name(id="getattr", ctx=ast.Load()),
                    args=[node.value, ast.Constant(node.attr)],
                    keywords=[]
                )
                return self.generic_visit(node)

        transformer = Transformer(self)
        self._code = transformer.visit(ast.parse(self._code))

    def _insert_dummy_comments(self) -> None:
        code_lines = self._code.splitlines()
        for index in range(len(code_lines) - 1, 0, -1):
            if random.randint(1, 10) > 7:  # Random chance to add dummy comments
                spaces = len(code_lines[index]) - len(code_lines[index].lstrip())
                dummy_comment = "# " + ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 50)))
                code_lines.insert(index, " " * spaces + dummy_comment)
        self._code = "\n".join(code_lines)

def main() -> None:
    # Command-line interface for the script
    parser = argparse.ArgumentParser(
        description="PyObfuscator: Obfuscates Python code to make it unreadable and hard to reverse."
    )
    parser.add_argument("--input", "-i", required=True, help="The file containing the code to obfuscate", metavar="PATH")
    parser.add_argument("--output", "-o", required=False,
                        help="The file to write the obfuscated code (defaults to Obfuscated_[input].py)",
                        metavar="PATH")
    parser.add_argument("--recursive", "-r", type=int, default=1,
                        help="Recursively obfuscates the code N times (slows down the code; not recommended)")
    parser.add_argument("--include_imports", "-m", action="store_true",
                        help="Include the import statements on the top of the obfuscated file")

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print("Input file does not exist.")
        exit(1)

    if not args.output:
        args.output = f"Obfuscated_{os.path.basename(args.input)}"

    # Read the input file
    with open(args.input, "r", encoding="utf-8") as file:
        contents = file.read()

    # Create the obfuscator object and obfuscate the code
    obfuscator = PyObfuscator(contents, args.include_imports, args.recursive)
    obfuscated_code = obfuscator.obfuscate()

    # Write the obfuscated code to the output file
    try:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(obfuscated_code)
        print(f"Your file has been successfully obfuscated and saved to {args.output}.")
    except Exception as e:
        print(f"Unable to save the file: {e}")

if __name__ == "__main__":
    main()
