/*string:1c0111001f010100061a024b53535009181c
XOR
686974207468652062756c6c277320657965
should produce:746865206b696420646f6e277420706c6179
*/
#include<bits/stdc++.h>
using namespace std;

vector<unsigned char> hex_to_bytes(const string& hex)
{
	vector<unsigned char> bytes;
	for(size_t i = 0;i < hex.length();i += 2)
	{
		string byteString = hex.substr(i,2);
		unsigned char byte =  static_cast<unsigned char>(strtol(byteString.c_str(),nullptr,16));
		bytes.push_back(byte); 
	}
	return bytes; 
}

vector<unsigned char> XORCalc(const vector<unsigned char>& s_1,const vector<unsigned char>& s_2)
{
	vector<unsigned char> res = s_1;
	for(size_t i = 0;i < s_1.size(); ++i)
		res[i] = s_1[i] ^ s_2[i];
	return res;
}

string bytes_to_hex(const vector<unsigned char>& bytes)
{
	stringstream ss;
	for(unsigned char byte : bytes)
		ss<<hex<<setw(2)<<setfill('0')<<(int)byte; 
	return ss.str();
}

int main()
{
	string s1 = "1c0111001f010100061a024b53535009181c";
	string s2 = "686974207468652062756c6c277320657965";
	
	vector<unsigned char> s_1,s_2,result;
	s_1 = hex_to_bytes(s1);
	s_2 = hex_to_bytes(s2);
	result = XORCalc(s_1,s_2);
	
	string res;
	res = bytes_to_hex(result);
	
	cout<<res;
	return 0;
} 