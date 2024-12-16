import os
import ast
import zlib
import base64
import string
import random
import argparse

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

    def _generate_random_name(self) -> str:
        return ''.join(random.choices(string.ascii_letters, k=random.randint(5, 20)))

    def _insert_dummy_comments(self) -> None:
        code_lines = self._code.splitlines()
        for index in range(len(code_lines) - 1, 0, -1):
            if random.randint(1, 10) > 7:
                spaces = len(code_lines[index]) - len(code_lines[index].lstrip())
                dummy_comment = "# " + ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 50)))
                code_lines.insert(index, " " * spaces + dummy_comment)
        self._code = "\n".join(code_lines)


def main() -> None:
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

    with open(args.input, "r", encoding="utf-8") as file:
        contents = file.read()

    obfuscator = PyObfuscator(contents, args.include_imports, args.recursive)
    obfuscated_code = obfuscator.obfuscate()

    try:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(obfuscated_code)
        print("Your file has been successfully obfuscated.")
    except Exception as e:
        print(f"Unable to save the file: {e}")


if __name__ == "__main__":
    main()
