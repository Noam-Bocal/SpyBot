# Setting Up Your Daemon
Follow the guide provided [here](https://betterprogramming.pub/unleashing-your-daemons-creating-services-on-ubuntu-731cd933e02e) to create your daemon. 
Please skip the "creating an executable" step. 

In the Environment field, make sure to add a path to the openssl-3.0.0 so that yara can work properly. In the User field, add your username. For the WorkingDirectory field, add the path to the directory where the Source of the Backend is located. In the ExecStart field, add the path to the Source of the Backend. You can leave the rest of the fields as they are in the example.

## Service Configuration
Here's a sample configuration for your service:

```ini
[Unit]
Description=My First Daemon!

[Service]
Environment="LD_LIBRARY_PATH=/home/user/openssl-3.0.0"
User=user
WorkingDirectory=/home/user/Desktop/implementations/Backend
ExecStart=/home/user/Desktop/implementations/Backend/Source
Type=simple
TimeoutStopSec=10
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```


# Driver Documentation
## Defines
```#define SPYBOT_IOC_MAGIC 'k' ``` - Unique identifier (magic number) for our driver's IOCTL commands, set to 'k.'

```#define SPYBOT_IOC_SIGNAL _IOWR(SPYBOT_IOC_MAGIC, 1, int) ``` - The IOCTL command for sending signals to a process.

```_IOWR(SPYBOT_IOC_MAGIC, 1, int) ``` - _IOWR is a linux micro that helps define IOCTL commands. The general syntax of it is: ```_IOWR(type, number, size)``` 

type - A unique identifier for the ioctl command, often referred to as the magic number.

number - A command number associated with a specific operation.

size - The size of the data involved in the ioctl operation.

## Device variables
```static int major_number ``` - Stores the dynamicly assigned major number which is an identidies the driver associated with the device file. More about this subject [here](https://www.oreilly.com/library/view/linux-device-drivers/0596000081/ch03s02.html)

```static struct cdev spybot_cdev ``` - Represents the character device within the kernel. It contains information and pointers to various functions associated with the character device, including file operations.

```static const struct file_operations spybot_fops; ``` - Defines the file operations that can be performed on the character device. It includes pointers to functions such as unlocked_ioctl for handling IOCTL commands.

## Functions
init_spybot: Initializes the SpyBot module when it enters the kernel. Registers the character device and sets up the major number, cdev structure, and file operations.

cleanup_spybot: Cleans up resources and unregisters the character device when the module exits the kernel.

sendSignalToTask: Sends the specified signal to the target process using the send_sig function.

spybot_ioctl: Handles SPYBOT_IOC_SIGNAL commands. Processes user requests to send signals (KILL, SUSPEND, CONT) to a specified process.


# Setting up network scanner
`sudo visudo
 //go to the end of the line
username ALL=NOPASSWD:your_command
//save and exit
sudo visudo -c //check for syntax error
`   


