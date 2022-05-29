using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int n = 0, breaker = 0;
            int pl = plainText.Length;
            for (int i = 0; i < pl; i++)//bnmshy 3laa el plain
            {
                if (cipherText[0] == plainText[i])//bnshof awl 7arf fi cipher hwa any 7arf fy plain
                {
                    int j = i + 1;//bygeb m3a kol lafa el7arf ely b3d el7arf dah
                    while (j < cipherText.Length)//bn5osh fe loop l 7ad ma elcipher t5ls
                    {
                        if (cipherText[1] == plainText[j])//lw tany 7arf fy cipher hwa hwa el7arf ely b3d el7arf elawl
                        {
                            int k = j + 1;//nafs klaam nshof ely b3do
                            while (k < cipherText.Length)//l 7ad ma cipher y5ls
                            {
                                if (k - j > j - i)// lw elmsafa ben el k w j akbr mn elmsafa ben j w i
                                {
                                    break;//m3nah an msh hwa fa atl3
                                }
                                else if (cipherText[2] == plainText[k] && k - j == j - i)// da m3nah an nafs elmsafa benhom
                                {
                                    n = j - i;//fa saglna el far2 3shan nemshy beh
                                    breaker = 1;
                                    break;
                                }
                                k++;

                            }
                        }
                        j++;
                        if (breaker == 1)
                            break;
                    }
                }
                if (breaker == 1)
                    break;
            }
            int columns = n;//weslna l 3add el coloumns
            List<int> key = new List<int>(columns);
            int rows = (int)Math.Ceiling(plainText.Length / (float)n);//3add rows
            char[,] table = new char[rows, columns];
            int counter0 = 0;
            for (int r = 0; r < rows; r++)//bnmla elmatrix b plaintext
            {
                for (int c = 0; c < columns; c++)
                {
                    if (counter0 < plainText.Length)//lw lesa plain m5lstsh bn7ot elba2y fe matrix
                    {
                        table[r, c] = plainText[counter0];
                        counter0++;
                    }
                    else//lw 5wlst bnmla b x
                    {
                        table[r, c] = 'x';
                    }
                }
            }
            for (int i = 0; i < columns; i++)//bnmshy 3la coloumns
            {
                int checker = 0;
                int pointer = 0;
                int counter = 2;
                for (int j = 0; j < rows; j++)
                {
                    //lw el cipher text weslna l a5erha aw el 7arf ely fy matrix hwa hw el7arf ely fy cipher
                    if ((pointer >= cipherText.Length || table[j, i] == cipherText[pointer]))
                    {
                        checker++;//bnzwd el check 3shan n3rf kam 7arf sa7
                        if (checker >= rows)//3shan n3rf homa sa7 wlaa
                        { key.Add((int)Math.Ceiling(pointer / (float)rows)); break; }//bnzwd elcolumn dah
                        pointer++;

                    }
                    else
                    {
                        j = -1;//3shan yerg3 ybd2 mn elawl 3la rows
                        int counterinc = counter++;
                        pointer = counterinc * rows - rows;//brg3 elpointer mn tany ll hagm ely kan ablo abl ma y5osh sa7
                    }
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // throw new NotImplementedException();
            int columns = key.Count;
            int rows = cipherText.Length / columns;
            char[,] table = new char[rows, columns];
            string plain = "";
            int counter = 1, count2 = 0;
            for (int c = 0; c < columns; c++)
            {
                if (counter == key[c] && counter <= key.Count)
                {
                    for (int r = 0; r < rows; r++)
                    {
                        if (count2 <= cipherText.Length)
                        {
                            table[r, c] = cipherText[count2];
                            count2++;
                        }
                    }
                    counter++;
                    c = -1;
                }
            }
            for (int i = 0; i < rows; i++)
            {
                for (int z = 0; z < columns; z++)
                {
                    plain += table[i, z];
                }
            }
            return plain.ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int columns = key.Count;//b3rf 3add el col mn 3add elkeys
            int rows = (int)Math.Ceiling((double)plainText.Length / columns);//3add el rows mn ta2semt el kelma 3la elcol
            char[,] table = new char[rows, columns];//matrix mn row x col
            string ciphe = "";
            int mycount = key.Count;
            int counter = 0;
            for (int r = 0; r < rows; r++)//blf 3la elmatrix
            {
                for (int c = 0; c < columns; c++)
                {
                    if (counter < plainText.Length)//lw la2et en el counter a2l mn tol elkelma(m3nah elkelma lesa m5lstsh)
                    {
                        table[r, c] = plainText[counter];//b7ot fy elmatrix 7arf mn kelmaa
                        counter++;
                    }
                    else//lw elkelma 5elst bmlah elba2y b x
                    {
                        table[r, c] = 'x';
                    }
                }
            }
            Dictionary<int, int> mydic = new Dictionary<int, int>();
            for (int i = 0; i < mycount; i++)//bmshy 3laa elkey
            {
                mydic[key[i] - 1] = i;//b5ly el key zero based
            }
            int m = 0;
            while (m < mycount)//bmshy 3la coloumn
            {
                for (int z = 0; z < rows; z++)//bmshy 3la elrows
                {
                    ciphe += table[z, mydic[m]];//bzod row w ana msbt elcoloumn 3shan a2ra elcol ely fy key
                }
                m++;
            }
            return ciphe.ToUpper();
        }
    }
}