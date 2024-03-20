using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.IO;
using System.Security.Cryptography;

namespace UIclient2
{
    class Communication
    {
        private const int SIZE_OF_BYTE = 8;
        static TcpClient client;
        public bool end;
        public bool msgAlive;

        private const int PORT = 8876;

        public async void msg()
        {
            if (!msgAlive)
            {
                Thread.Sleep(1000);
                Thread wait = new Thread(msg);
                wait.Start();
            }
        }

        public Communication()
        {
            client = new TcpClient();
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), PORT);
            msgAlive = true;
            while (!client.Connected)
            {
                try
                {
                    client.Connect(serverEndPoint);
                }
                catch
                {
                    if (msgAlive)
                    {
                        msgAlive = false;
                        Thread wait = new Thread(msg);
                        wait.Start();
                    }
                }
            }
            msgAlive = true;
        }

        public static string SerializationString(string str)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(str);
            string binaryString = string.Join("", bytes.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
            return binaryString;
        }

        public static string DeserializationString(byte[] binary)
        {
            return Encoding.UTF8.GetString(binary);
        }

        public static void SendMSG(int code, string json)
        {
            string msg = "";
            msg += code.ToString();
            NetworkStream clientStream = client.GetStream();
            msg += json.Length.ToString().PadLeft(4, '0');
            msg += json;
            string buffer = SerializationString(msg);
            clientStream.Write(Encoding.UTF8.GetBytes(buffer), 0, buffer.Length);
            clientStream.Flush();
        }

        public static string GetPartFromSocket(int bytesNum)
        {
            NetworkStream clientStream = client.GetStream();
            byte[] data = new byte[bytesNum];

            int bytesRead = clientStream.Read(data, 0, bytesNum);

            if (bytesRead == 0)
            {
                string errorMsg = $"Error while receiving from socket: {clientStream}";
                throw new InvalidOperationException(errorMsg);
            }

            data[0] = 0;
            return Encoding.UTF8.GetString(data);
        }

        public static string GetMSG()
        {
            string buffer = GetPartFromSocket(SIZE_OF_BYTE);
            string ascii = BinaryStringToAscii(buffer);
            if (ascii[0] == '\0')
            {
                buffer = GetPartFromSocket(3 * SIZE_OF_BYTE);

            }
            else
            {
                buffer += GetPartFromSocket(2 * SIZE_OF_BYTE);
            }

            // Getting the data length
            string dataLength = GetPartFromSocket(4 * SIZE_OF_BYTE);
            buffer += dataLength;
            dataLength = BinaryStringToAscii(dataLength);
            string length = "";

            // Getting the data from the packet
            int dataSize = int.Parse(dataLength) * SIZE_OF_BYTE;
            buffer += GetPartFromSocket(dataSize);
            return BinaryStringToAscii(buffer);
        }

        public static string BinaryStringToAscii(string str)
        {
             // To store size of s
            int N = (str.Length);
    
            // If given String is not a
            // valid String
            if (N % 8 != 0) {
                return "Not Possible!";
            }
    
            // To store final answer
            string res = "";
    
            // Loop to iterate through String
            for (int i = 0; i < N; i += 8) {
                int decimal_value
                    = binaryToDecimal((str.Substring(i, 8)));
    
                // Apprend the ASCII character
                // equivalent to current value
                res += (char)(decimal_value);
            }
    
            // Return Answer
            return res;
        }
        private static int binaryToDecimal(string n)
        {
            string num = n;
 
            // Stores the decimal value
            int dec_value = 0;
    
            // Initializing base value to 1
            int base1 = 1;
    
            int len = num.Length;
            for (int i = len - 1; i >= 0; i--) {
    
                // If the current bit is 1
                if (num[i] == '1')
                    dec_value += base1;
                base1 = base1 * 2;
            }
    
            // Return answer
            return dec_value;
        }

        public static string HashFile(string filename, string algorithmName = "SHA256")
        {
            // Open the file in binary mode
            using (FileStream file = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                // Create a new hash algorithm instance
                using (HashAlgorithm hashAlgorithm = HashAlgorithm.Create(algorithmName))
                {
                    if (hashAlgorithm == null)
                        throw new InvalidOperationException("Failed to create hash algorithm");

                    // Compute the hash
                    byte[] hashBytes = hashAlgorithm.ComputeHash(file);

                    // Convert the hash bytes to a hexadecimal string
                    StringBuilder stringBuilder = new StringBuilder();
                    foreach (byte b in hashBytes)
                    {
                        stringBuilder.Append(b.ToString("x2"));
                    }
                    return stringBuilder.ToString();
                }
            }
        }

    }    
}
