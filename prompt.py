import glob

task = """
Please review and recommend improvements for the following code.
It is a user service which might be initiated with different providers based on the definition in a JSON config file.
"""

print(task)

for path in glob.glob("pkg/service/user/**.go"):
    print("```golang")
    print(f"// {path}")
    with open(path) as f:
        for line in f:
            print(line.strip("\n"))
    print("```")