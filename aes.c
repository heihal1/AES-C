#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
* 明文数组：plain_text（16位一维数组）
* 初始密钥数组：cipher_text（16位一维数组）
* 将输入的一维明文数组装载进4×4状态矩阵（state）中，使用4×4状态矩阵（state）进行后续计算：state
* 将输入的一维初始密钥数组装载进4×4密钥矩阵（key）中，使用4×4密钥矩阵（key）进行后续密钥扩展计算：key
* 明文经过整个加密过程后得到的结果：cipher_text
* S盒：S_Box
* 逆S盒：inv_S_Box
* 字节代换：SubBytes
* 逆字节代换：inv_SubBytes
* 行移位：ShiftRows
* 逆行移位：inv_ShiftRows
* 列混淆：MixColumns
* 逆列混淆：inv_MixColumns
* 轮密钥加：AddRoundKey
* 逆轮密钥加（轮密钥加和逆轮密钥加相同因为异或的逆运算还是异或）：inv_AddRoundKey
* 
*/

const static int S_Box[256] =
{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const static int inv_S_Box[256] =
{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const unsigned int MixArray[4][4] =
{
	0x02, 0x03, 0x01, 0x01,
	0x01, 0x02, 0x03, 0x01,
	0x01, 0x01, 0x02, 0x03,
	0x03, 0x01, 0x01, 0x02
};

const unsigned int ConvertMixArray[4][4] =
{
	0x0e, 0x0b, 0x0d, 0x09,
	0x09, 0x0e, 0x0b, 0x0d,
	0x0d, 0x09, 0x0e, 0x0b,
	0x0b, 0x0d, 0x09, 0x0e
};

int GaloisMultiple(unsigned int left, unsigned int right)
{

	unsigned int result = 0;

	while (left)
	{

		if (left & 0x00000001)
		{
			result ^= right;
		}


		left = left >> 1;


		if (right & 0x0000080)
		{

			right = right << 1;

			right = right & (0X000000FF);

			right ^= 0x0000001B;
		}
		else
		{

			right = right << 1;
		}
	}
	return result;
}


//轮密钥加函数
void Addroundkey(int(*state)[4], int(*key)[4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[i][j] = state[i][j] ^ key[i][j];//轮密钥加 = 将生成的轮密钥和状态矩阵相异或 
		}
	}
}


//字节替换函数
int SubBytes(int(*state)[4]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = S_Box[state[i][j]];//以状态矩阵中的值作为坐标在S盒中查找替换
		}
	}
	return 0;
}

//逆字节替换函数
int inv_SubBytes(int(*state)[4]) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = inv_S_Box[state[i][j]];
		}
	}
	return 0;
}

// 打印矩阵函数
void print(int(*state)[4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			printf("%2x，", state[i][j]);
		}
		printf("\n");
	}
}

//行移位函数
void ShiftRows(int(*arry)[4])
{
	int temp10;
	int temp20;
	int temp21;
	int temp30;
	int temp31;
	int temp32;

	temp10 = arry[1][0];
	for (int i = 0; i < 3; i++)
	{
		arry[1][i] = arry[1][i + 1];
	}
	arry[1][3] = temp10;             //second line

	temp20 = arry[2][0];
	temp21 = arry[2][1];
	arry[2][0] = arry[2][2];
	arry[2][1] = arry[2][3];
	arry[2][2] = temp20;
	arry[2][3] = temp21;           //third line

	temp30 = arry[3][0];
	temp31 = arry[3][1];
	temp32 = arry[3][2];
	arry[3][0] = arry[3][3];
	arry[3][1] = temp30;
	arry[3][2] = temp31;
	arry[3][3] = temp32;           //fourth line

}

//逆行移位函数
void inv_ShiftRows(int(*arry)[4])
{
	int temp13;
	int temp23;
	int temp22;
	int temp30;
	int temp31;
	int temp32;
	int temp33;


	temp13 = arry[1][3];
	for (int i = 3; i > 0; i--)
	{
		arry[1][i] = arry[1][i - 1];
	}
	arry[1][0] = temp13;             //second line

	temp23 = arry[2][3];
	temp22 = arry[2][2];
	arry[2][3] = arry[2][1];
	arry[2][2] = arry[2][0];
	arry[2][1] = temp23;
	arry[2][0] = temp22;           //third line

	temp30 = arry[3][0];
	temp31 = arry[3][1];
	temp32 = arry[3][2];
	temp33 = arry[3][3];
	arry[3][0] = temp31;
	arry[3][1] = temp32;
	arry[3][2] = temp33;
	arry[3][3] = temp30;                //fourth line

}

//列混淆函数
int MixColumns(unsigned int(*PlainArray)[4], char convert)
{

	unsigned int ArrayTemp[4][4];

	int x, y;
	for (x = 0; x < 4; x++)
	{
		for (y = 0; y < 4; y++)
		{
			ArrayTemp[x][y] = *(PlainArray[x] + y);
		}
	}


	int i, j;
	if (convert == 0)
	{
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				*(PlainArray[i] + j) =
					GaloisMultiple(MixArray[i][0], ArrayTemp[0][j]) ^
					GaloisMultiple(MixArray[i][1], ArrayTemp[1][j]) ^
					GaloisMultiple(MixArray[i][2], ArrayTemp[2][j]) ^
					GaloisMultiple(MixArray[i][3], ArrayTemp[3][j]);
			}
		}
	}
	else
	{
		for (i = 0; i < 4; i++)
		{
			for (j = 0; j < 4; j++)
			{
				*(PlainArray[i] + j) =
					GaloisMultiple(ConvertMixArray[i][0], ArrayTemp[0][j]) ^
					GaloisMultiple(ConvertMixArray[i][1], ArrayTemp[1][j]) ^
					GaloisMultiple(ConvertMixArray[i][2], ArrayTemp[2][j]) ^
					GaloisMultiple(ConvertMixArray[i][3], ArrayTemp[3][j]);
			}
		}
	}

	return 0;
}

//密钥扩展函数
void KeyExpansion(int(*key)[4], int round)
{
	//将待扩展的4×4密钥矩阵中的每一个元素都暂存进temp中
	int temp00 = key[0][0];
	int temp01 = key[0][1];
	int temp02 = key[0][2];
	int temp03 = key[0][3];
	int temp10 = key[1][0];
	int temp11 = key[1][1];
	int temp12 = key[1][2];
	int temp13 = key[1][3];
	int temp20 = key[2][0];
	int temp21 = key[2][1];
	int temp22 = key[2][2];
	int temp23 = key[2][3];
	int temp30 = key[3][0];
	int temp31 = key[3][1];
	int temp32 = key[3][2];
	int temp33 = key[3][3];

	/*
	* 密钥扩展函数使用一次只扩展四位，举例：待扩展密钥为W[0] - W[3]，需要使用密钥扩展函数得到W[4] - W[7]，所以：
	W[4] = W[0] ⨁ T(W[3])；（335行 - 338行）
	W[5] = W[1] ⨁ W[4]；（340行 - 343行）
	W[6] = W[2] ⨁ W[5]；（345行 - 348行）
	W[7] = W[3] ⨁ W[6]；（350行 - 353行）
	经过密钥扩展函数计算后，密钥矩阵从原来的W[0] - W[3]变为W[4] - W[7]，此时W[4] - W[7]变为了新的W[0] - W[3]
	下一次使用密钥扩展函数时，重复上述过程，重复10次即得到十轮轮密钥

	* T0 T1 T2 T3分别表示W[3]中四个元素经过T函数变换后的值：
	* 首先将T0 T1 T2 T3分别初始化为0（307行 - 310行）；
	* 根据 T 函数的定义，分别进行字循环（319行 - 322行）、字节替换（324行 - 327行）、轮常量异或（331行 - 334行）；
	*/
	
	int T0 = 0;
	int T1 = 0;
	int T2 = 0;
	int T3 = 0;

	T0 = temp13;
	T1 = temp23;
	T2 = temp33;
	T3 = temp03;

	T0 = S_Box[T0];
	T1 = S_Box[T1];
	T2 = S_Box[T2];
	T3 = S_Box[T3];

	int Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

	T0 = T0 ^ Rcon[round - 1];
	T1 = T1 ^ 0;
	T2 = T2 ^ 0;
	T3 = T3 ^ 0;

	key[0][0] = temp00 ^ T0;
	key[1][0] = temp10 ^ T1;
	key[2][0] = temp20 ^ T2;
	key[3][0] = temp30 ^ T3;

	key[0][1] = temp01 ^ key[0][0];
	key[1][1] = temp11 ^ key[1][0];
	key[2][1] = temp21 ^ key[2][0];
	key[3][1] = temp31 ^ key[3][0];

	key[0][2] = temp02 ^ key[0][1];
	key[1][2] = temp12 ^ key[1][1];
	key[2][2] = temp22 ^ key[2][1];
	key[3][2] = temp32 ^ key[3][1];

	key[0][3] = temp03 ^ key[0][2];
	key[1][3] = temp13 ^ key[1][2];
	key[2][3] = temp23 ^ key[2][2];
	key[3][3] = temp33 ^ key[3][2];
}

//加密函数：首先进行一次密钥扩展得到新的key，随后对state进行SubBytes、ShiftRows、MixColumns，再使用经过SubBytes、ShiftRows、MixColumns得到的新的state和密钥扩展得到的新的key进行Addroundkey
void encryption(int(*state)[4], int(*key)[4], int round)
{
	KeyExpansion(key, round);
	printf("The key after %x round KeyExpansion is ：\n", round);
	print(key);
	printf("\n");

	SubBytes(state);
	printf("Encryption: The state after SubBytes of the %x round is ：\n", round);
	print(state);
	printf("\n");


	ShiftRows(state);
	printf("Encryption: The state after ShiftRows of the %x round is ：\n", round);
	print(state);
	printf("\n");

	MixColumns(state, 0);
	printf("Encryption: The state after MixColumns of the %x round is ：\n", round);
	print(state);
	printf("\n");

	Addroundkey(state, key);
	printf("Encryption: The state after the Addroundkey of the %x round is ：\n", round);
	print(state);
	printf("\n");
}


void Final_Round_Encryption(int(*state)[4], int(*key)[4], int round)
{
	KeyExpansion(key, round);
	printf("Encryption: The key after %d round KeyExpansion is ：\n", round);
	print(key);
	printf("\n");

	SubBytes(state);
	printf("Encryption: The state after SubBytes of the %d round is ：\n", round);
	print(state);
	printf("\n");

	ShiftRows(state);
	printf("Encryption: The state after ShiftRows of the %d round is ：\n", round);
	print(state);
	printf("\n");

	Addroundkey(state, key);
	printf("Encryption: The state after the Addroundkey of the %d round is ：\n", round);
	print(state);
	printf("\n");
}

void load_expanded_key_to_tempkey(int(*expanded_key)[4], int(*key)[4])
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			expanded_key[i][j] = key[i][j];
		}
	}
}

void decryption(int(*state)[4], int(*newkey)[4], int round)
{
	Addroundkey(state, newkey);
	printf("Decryption: The text matrix after the inv_AddRoundKey for the %d time is ：\n", round);
	print(state);
	printf("\n");

	MixColumns(state, 1);
	printf("Decryption: The state after the inv_MixColumns of the %x round is ：\n", round);
	print(state);
	printf("\n");

	inv_ShiftRows(state);
	printf("Decryption: The state after the inv_ShiftRows of the %d round is ：\n", round);
	print(state);
	printf("\n");

	inv_SubBytes(state);
	printf("Decryption: The state after the inv_SubBytes of the %d round is ：\n", round);
	print(state);
	printf("\n");

}

void Final_Round_Decryption(int(*state)[4], int(*newkey)[4], int round)
{
	Addroundkey(state, newkey);
	printf("Decryption: The state after the inv_AddRoundKey of the %d round is ：\n", round);
	print(state);
	printf("\n");

	inv_ShiftRows(state);
	printf("Decryption: The state after inv_ShiftRows of the %d round is ：\n", round);
	print(state);
	printf("\n");

	inv_SubBytes(state);
	printf("Decryption: The state after inv_SubBytes of the %d round is ：\n", round);
	print(state);
	printf("\n");

}

void main()
{
	//以下注释部分为键盘输入明文矩阵和初始密钥矩阵：

	/*int plain_text[16] = { 0 };
	int cipher_key[16] = { 0 };

	for (int i = 0; i < 16; i++)
	{
			printf("请输入第%d个文本",i+1);
			scanf_s("%x", plain_text + i);
	}

	int state[4][4] = { 0 };

	int k = 0;
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[i][j] = plain_text[k];
			k++;
		}
	}

	for (int i = 0; i < 16; i++)
	{
		printf("请输入第%d个密钥", i + 1);
		scanf_s("%x", cipher_key + i);
	}

	int key[4][4] = { 0 };

	int o = 0;
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			key[i][j] = cipher_key[o];
			o++;
		}
	}*/

	int state[4][4] =
	{
		0x32, 0x88, 0x31, 0xe0,
		0x43, 0x5a, 0x31, 0x37,
		0xf6, 0x30, 0x98, 0x07,
		0xa8, 0x8d, 0xa2, 0x34
	};

	int key[4][4] =
	{
		0x2b, 0x28, 0xab, 0x09,
		0x7e, 0xae, 0xf7, 0xcf,
		0x15, 0xd2, 0x15, 0x4f,
		0x16, 0xa6, 0x88, 0x3c
	};

	int tempkey[4][4] = { 0 };
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			tempkey[i][j] = key[i][j];// Use tempkey to store the cipher key matrix
		}
	}


	printf("\n");
	printf("The plain text matrix is ：\n");
	print(state);
	printf("\n");
	printf("The cipher key matrix is ：\n");
	print(key);
	printf("\n");



	int newkey1[4][4] = { 0 };
	int newkey2[4][4] = { 0 };
	int newkey3[4][4] = { 0 };
	int newkey4[4][4] = { 0 };
	int newkey5[4][4] = { 0 };
	int newkey6[4][4] = { 0 };
	int newkey7[4][4] = { 0 };
	int newkey8[4][4] = { 0 };
	int newkey9[4][4] = { 0 };
	int newkey10[4][4] = { 0 };

	Addroundkey(state, key);//(initial round)
	printf("Encryption: The plain text matrix after the initial round is ：\n");
	print(state);
	printf("\n");

	encryption(state, key, 1);//第一轮加密
	load_expanded_key_to_tempkey(newkey1, key);

	encryption(state, key, 2);//第二轮加密
	load_expanded_key_to_tempkey(newkey2, key);

	encryption(state, key, 3);//第三轮加密
	load_expanded_key_to_tempkey(newkey3, key);

	encryption(state, key, 4);//第四轮加密
	load_expanded_key_to_tempkey(newkey4, key);

	encryption(state, key, 5);//第五轮加密
	load_expanded_key_to_tempkey(newkey5, key);

	encryption(state, key, 6);//第六轮加密
	load_expanded_key_to_tempkey(newkey6, key);

	encryption(state, key, 7);//第七轮加密
	load_expanded_key_to_tempkey(newkey7, key);

	encryption(state, key, 8);//第八轮加密
	load_expanded_key_to_tempkey(newkey8, key);

	encryption(state, key, 9);//第九轮加密
	load_expanded_key_to_tempkey(newkey9, key);

	Final_Round_Encryption(state, key, 10);//第十轮（final round）加密
	load_expanded_key_to_tempkey(newkey10, key);


	Final_Round_Decryption(state, newkey10, 1);
	decryption(state, newkey9, 2);
	decryption(state, newkey8, 3);
	decryption(state, newkey7, 4);
	decryption(state, newkey6, 5);
	decryption(state, newkey5, 6);
	decryption(state, newkey4, 7);
	decryption(state, newkey3, 8);
	decryption(state, newkey2, 9);
	decryption(state, newkey1, 10);

	Addroundkey(state, tempkey);// tempkey == cipher key matrix
	printf("Decryption: The state after the initial round is ：\n");
	print(state);
	printf("\n");
}


