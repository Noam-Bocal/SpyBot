import subprocess

MODULE_NAME = "spybot"

command = "dmesg | grep " + MODULE_NAME + " | tail"

loggs = []

try:
    # Run the shell command and capture the output
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for the process to finish and get the output
    stdout, stderr = process.communicate()
    
    data = stdout.decode('utf-8')
    for line in data.split('\n'):
        line_data = line.split(' | ')
        log = {}
        for piece in line_data:
            info = piece.split(": ")
            if len(info) == 2:
                if MODULE_NAME in info[0]:
                    log[MODULE_NAME] = [info[1], info[0].split(" ")[0]]
                    continue
                log[info[0]] = info[1]
            loggs.append(log)
        print(log)


except Exception as e:
    print("Error:", str(e))




