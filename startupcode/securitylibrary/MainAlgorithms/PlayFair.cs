using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;



namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        char[,] keyMatrix = new char[5, 5];
        void findInMatrix(char letter, ref int row, ref int col)
        {
            for (int r = 0; r < 5; ++r)
                for (int c = 0; c < 5; ++c)
                    if (letter == keyMatrix[r, c])
                    {
                        row = r; col = c;



                    }
        }
        bool found(char c, char[] arrd)
        {
            bool find = false;
            for (int i = 0; i < 25; i++)
            {
                if (c == arrd[i])
                {
                    find = true;
                    break;
                }



            }
            return find;
        }
        public string rem_x(string plain_text)
        {
            string value = plain_text.Substring(0, 1);
            for (int i = 1; i < plain_text.Length - 1; i++)
            {
                if (!(plain_text[i] == 'x' && plain_text[i - 1] == plain_text[i + 1] && i % 2 != 0))
                {
                    value += plain_text.Substring(i, 1);
                }
            }
            if (plain_text[plain_text.Length - 1] != 'x')
                value += plain_text.Substring(plain_text.Length - 1, 1);
            return value;
        }
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }



        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            string plain_text1 = "";
            char fillLetter = 'a';
            int count = 0;
            int index = 1;
            char[] added = new char[26];//save letters of the matrix
            added[0] = 'j';
            cipherText = cipherText.ToLower();
            for (int row = 0; row < 5; ++row)
                for (int col = 0; col < 5; ++col) //fill matrix
                {
                    if (count < key.Length)
                    { // insert key 
                        char letter = key[count];
                        if (!found(letter, added))
                        {
                            keyMatrix[row, col] = letter;
                            added[index] = letter;
                            index++;
                        }
                        else --col;
                        ++count;
                    }
                    else
                    { // fill matrix when key is inserted
                        if (!found(fillLetter, added))
                            keyMatrix[row, col] = fillLetter;
                        else --col;
                        ++fillLetter;
                    }
                }
            int row1 = 0, col1 = 0, row2 = 0, col2 = 0;
            for (int k = 0; k < cipherText.Length; k += 2)//cases of cipher
            {
                findInMatrix(cipherText[k], ref row1, ref col1);
                findInMatrix(cipherText[k + 1], ref row2, ref col2);
                if (row1 == row2)
                {
                    plain_text1 += keyMatrix[row1, (col1 + 4) % 5];
                    plain_text1 += keyMatrix[row2, (col2 + 4) % 5];
                }
                else if (col1 == col2)
                {
                    plain_text1 += keyMatrix[(row1 + 4) % 5, col1];
                    plain_text1 += keyMatrix[(row2 + 4) % 5, col2];
                }
                else
                {
                    plain_text1 += keyMatrix[row1, col2];
                    plain_text1 += keyMatrix[row2, col1];
                }
            }
            plain_text1 = rem_x(plain_text1);//remove x from odd plaintext and duplicate letters
            Console.WriteLine(plain_text1);
            return plain_text1;
        }



        public string Encrypt(string plainText, string key)
        {
            string cipher_text = "";
            int index = 1;
            char[] added = new char[26];
            added[0] = 'j';
            int size = key.Length;
            int count = 0;
            char fillLetter = 'a';
            int size2 = plainText.Length;
            key = key.ToLower();
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }
            if (plainText.Length % 2 != 0)
            {
                plainText += 'x';
            }

            for (int row = 0; row < 5; ++row)
                for (int col = 0; col < 5; ++col)
                {
                    if (count < size)
                    { // insert key 
                        char letter = key[count];
                        if (!found(letter, added))
                        {
                            keyMatrix[row, col] = letter;
                            added[index] = letter;
                            index++;
                        }
                        else --col;
                        ++count;
                    }
                    else
                    { // fill matrix when key is inserted
                        if (!found(fillLetter, added))



                            keyMatrix[row, col] = fillLetter;
                        else --col;
                        ++fillLetter;
                    }
                }
            int row1 = 0, col1 = -1, row2 = 0, col2 = -1;
            for (int k = 0; k < plainText.Length; k += 2)
            {
                findInMatrix(plainText[k], ref row1, ref col1);
                findInMatrix(plainText[k + 1], ref row2, ref col2);



                if (row1 == row2)
                {
                    cipher_text += keyMatrix[row1, (col1 + 1) % 5];
                    cipher_text += keyMatrix[row2, (col2 + 1) % 5];
                }



                else if (col1 == col2)
                {
                    cipher_text += keyMatrix[(row1 + 1) % 5, col1];
                    cipher_text += keyMatrix[(row2 + 1) % 5, col2];
                }



                else
                {
                    cipher_text += keyMatrix[row1, col2];
                    cipher_text += keyMatrix[row2, col1];
                }



            }



            return cipher_text;
        }
    }
}