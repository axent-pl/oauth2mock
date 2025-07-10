import glob

task = """
Given the golang package code please review it and add documentation.
"""

print(task)

for path in glob.glob("pkg/sessionservice/**.go"):
    print("```golang")
    print(f"// {path}")
    with open(path) as f:
        for line in f:
            print(line.strip("\n"))
    print("```")