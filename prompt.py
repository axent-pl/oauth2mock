import glob

task = """
Given the golang package code please implement a functionality which will check if ther users table
is created, has the correct schema and if not will apply required DDL.
"""

print(task)

for path in glob.glob("pkg/service/user/**.go"):
    print("```golang")
    print(f"// {path}")
    with open(path) as f:
        for line in f:
            print(line.strip("\n"))
    print("```")