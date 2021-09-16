// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

/* Generate random bytes*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;
#include <fstream>
using std::ifstream;
#include <string>
using std::string;
using std::wstring;

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

#include <cstdlib>
using std::exit;

#include <cryptopp/files.h>
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/cryptlib.h"
using CryptoPP::byte;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/des.h"
using CryptoPP::DES;
#include <cryptopp/modes.h>
#include "cryptopp/ccm.h"
using namespace CryptoPP;
// using CryptoPP::CBC_Mode;
// using CryptoPP::CCM_Mode;
// using CryptoPP::CFB_Mode;
// using CryptoPP::CTR_Mode;
// using CryptoPP::ECB_Mode;
// using CryptoPP::GCM_Mode;
// using CryptoPP::OFB_Mode;
// using CryptoPP::XTS_Mode;
#include <cryptopp/gcm.h>
#include <cryptopp/xts.h>
#include "assert.h"

/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* Save and load key */
void Save(const string &filename, const BufferedTransformation &bt);
void Load(const string &filename, BufferedTransformation &bt);

void AES_CBC_Mode(const string &plain, CryptoPP::byte *key, byte *iv);
/* convert wstring to string */
string wstring_to_string(const wstring &str);
/* convert string to wstring */
wstring string_to_wstring(const string &str);

int main(int argc, char *argv[])
{
#ifdef __linux__
	setlocale(LC_ALL, "");
#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif
	// 0. variables declaration
	wstring wplain;
	string plain;
	wstring mode[8] = {L"ECB", L"CBC", L"OFB", L"CFB", L"CTR"};
	int selected_mode_index;
	wstring selected_mode;
	wstring key_input_mode[3] = {L"randomly", L"from screen", L"files"};
	int selected_key_input_mode_index;
	wstring selected_key_input_mode;
	// Secret_Key_IV secret_key_iv;
	string cipher, encoded, recovered;
	CryptoPP::byte key[64];
	byte iv[DES::BLOCKSIZE];

	// INPUT the message from screen
	wcout << ">> Enter your message: ";
	getline(wcin, wplain);
	plain = wstring_to_string(wplain);

	// INPUT mode
	wcout << "List of modes: " << endl;
	for (int i = 0; i < 5; i++)
	{
		wcout << i + 1 << ": " << mode[i] << endl;
	}
	wcout << ">> Select the mode (1->5): ";
	wcin >> selected_mode_index;
	selected_mode = mode[selected_mode_index - 1];
	wcout << "Method " << selected_mode << " is selected" << endl;

	// INPUT key and IV
	wcout << "Input method for key and IV: " << endl;
	for (int i = 0; i < 3; i++)
	{
		wcout << i + 1 << ": " << key_input_mode[i] << endl;
	}
	wcout << ">> Select the mode (1->3): ";
	wcin >> selected_key_input_mode_index;
	selected_key_input_mode = key_input_mode[selected_key_input_mode_index - 1];
	wcout << "Secret key and IV will be added " << selected_key_input_mode << endl;
	switch (selected_key_input_mode_index)
	{
	case 1:
	{
		AutoSeededRandomPool prng;
		prng.GenerateBlock(key, sizeof(key));
		prng.GenerateBlock(iv, sizeof(iv));
		break;
	}
	case 2:
	{
		string pkey;
		wstring wpkey;
		wcout << "Input key (at least 16 bytes): ";
		wcin >> wpkey;
		pkey = wstring_to_string(wpkey);
		/* Reading key from  input screen*/
		StringSource ss(pkey, false);
		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(key, sizeof(key));
		/*Copy data to key*/
		ss.Detach(new Redirector(copykey));
		ss.Pump(64); // Pump first 16 bytes
		string temp_iv;
		wstring temp_wiv;
		wcout << "Input IV (at least 16 bytes): ";
		wcin >> temp_wiv;
		temp_iv = wstring_to_string(temp_wiv);
		/* Reading iv from  input screen*/
		StringSource ss2(temp_iv, false);
		/* Create byte array space for iv*/
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data to iv*/
		ss2.Detach(new Redirector(copyiv));
		ss2.Pump(16); // Pump first 16 bytes
		break;
	}
	case 3:
	{
		string temp_key, temp_iv;
		string text;
		wstring file_path = L"secret_key_and_iv.txt";
		wcout << "Input file path (secret_key_and_iv.txt): " << endl;
		// wcin >> file_path
		ifstream MyReadFile(wstring_to_string(file_path));
		int counter = 0;
		while (getline(MyReadFile, text))
		{
			std::cout << text;
			if (counter == 2)
			{
				break;
			}
			if (counter == 0)
			{
				temp_key = text;
			}
			else
			{
				temp_iv = text;
			}
			counter++;
		}
		MyReadFile.close();

		StringSource ss(temp_key, false);
		/* Create byte array space for key*/
		CryptoPP::ArraySink copykey(key, sizeof(key));
		/*Copy data to key*/
		ss.Detach(new Redirector(copykey));
		ss.Pump(64); // Pump first 16 bytes
		/* Reading iv from  input screen*/
		StringSource ss2(temp_iv, false);
		/* Create byte array space for iv*/
		CryptoPP::ArraySink copyiv(iv, sizeof(iv));
		/*Copy data to iv*/
		ss2.Detach(new Redirector(copyiv));
		ss2.Pump(64); // Pump first 16 bytes
		break;
	}
	default:
		break;
	}

	// secret_key_iv = get_secret_key_iv(selected_key_input_mode);

	// PROCESSING
	switch (selected_mode_index)
	{
	case 1:
	{
		CryptoPP::byte the_key[DES::DEFAULT_KEYLENGTH];
		std::copy(key + 0, key + DES::DEFAULT_KEYLENGTH, the_key);
		// Pretty print key
		encoded.clear();
		StringSource(the_key, sizeof(the_key), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "key: " << string_to_wstring(encoded) << endl;
		// Pretty print IV
		encoded.clear();
		StringSource(iv, sizeof(iv), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "iv: " << string_to_wstring(encoded) << endl;
		try
		{
			ECB_Mode<DES>::Encryption e;
			e.SetKey(the_key, sizeof(the_key));
			StringSource s1(plain, true,
							new StreamTransformationFilter(e,
														   new StringSink(cipher)) // StreamTransformationFilter
			);
			ECB_Mode<DES>::Decryption d;
			d.SetKey(the_key, sizeof(the_key));
			StringSource s2(cipher, true,
							new StreamTransformationFilter(d,
														   new StringSink(recovered)) // StreamTransformationFilter
			);																		  // StringSource
		}
		catch (const CryptoPP::Exception &e)
		{
			cerr << e.what() << endl;
			exit(1);
		}
		break;
	}
	case 2:
	{
		CryptoPP::byte the_key[DES::DEFAULT_KEYLENGTH];
		std::copy(key + 0, key + DES::DEFAULT_KEYLENGTH, the_key);
		// Pretty print key
		encoded.clear();
		StringSource(the_key, sizeof(the_key), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "key: " << string_to_wstring(encoded) << endl;
		// Pretty print IV
		encoded.clear();
		StringSource(iv, sizeof(iv), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "iv: " << string_to_wstring(encoded) << endl;
		try
		{
			CBC_Mode<DES>::Encryption e;
			e.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s1(plain, true,
							new StreamTransformationFilter(e,
														   new StringSink(cipher)) // StreamTransformationFilter
			);
			CBC_Mode<DES>::Decryption d;
			d.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s2(cipher, true,
							new StreamTransformationFilter(d,
														   new StringSink(recovered)) // StreamTransformationFilter
			);																		  // StringSource
		}
		catch (const CryptoPP::Exception &e)
		{
			cerr << e.what() << endl;
			exit(1);
		}
		break;
	}
	case 3:
	{
		CryptoPP::byte the_key[DES::DEFAULT_KEYLENGTH];
		std::copy(key + 0, key + DES::DEFAULT_KEYLENGTH, the_key);
		// Pretty print key
		encoded.clear();
		StringSource(the_key, sizeof(the_key), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "key: " << string_to_wstring(encoded) << endl;
		// Pretty print IV
		encoded.clear();
		StringSource(iv, sizeof(iv), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "iv: " << string_to_wstring(encoded) << endl;
		try
		{
			OFB_Mode<DES>::Encryption e;
			e.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s1(plain, true,
							new StreamTransformationFilter(e,
														   new StringSink(cipher)) // StreamTransformationFilter
			);
			OFB_Mode<DES>::Decryption d;
			d.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s2(cipher, true,
							new StreamTransformationFilter(d,
														   new StringSink(recovered)) // StreamTransformationFilter
			);																		  // StringSource
		}
		catch (const CryptoPP::Exception &e)
		{
			cerr << e.what() << endl;
			exit(1);
		}
		break;
	}
	case 4:
	{
		CryptoPP::byte the_key[DES::DEFAULT_KEYLENGTH];
		std::copy(key + 0, key + DES::DEFAULT_KEYLENGTH, the_key);
		// Pretty print key
		encoded.clear();
		StringSource(the_key, sizeof(the_key), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "key: " << string_to_wstring(encoded) << endl;
		// Pretty print IV
		encoded.clear();
		StringSource(iv, sizeof(iv), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "iv: " << string_to_wstring(encoded) << endl;
		try
		{
			CFB_Mode<DES>::Encryption e;

			e.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s1(plain, true,
							new StreamTransformationFilter(e,
														   new StringSink(cipher)) // StreamTransformationFilter
			);
			CFB_Mode<DES>::Decryption d;
			d.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s2(cipher, true,
							new StreamTransformationFilter(d,
														   new StringSink(recovered)) // StreamTransformationFilter
			);																		  // StringSource
		}
		catch (const CryptoPP::Exception &e)
		{
			cerr << e.what() << endl;
			exit(1);
		}
		break;
	}
	case 5:
	{
		CryptoPP::byte the_key[DES::DEFAULT_KEYLENGTH];
		std::copy(key + 0, key + DES::DEFAULT_KEYLENGTH, the_key);
		// Pretty print key
		encoded.clear();
		StringSource(the_key, sizeof(the_key), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "key: " << string_to_wstring(encoded) << endl;
		// Pretty print IV
		encoded.clear();
		StringSource(iv, sizeof(iv), true,
					 new HexEncoder(
						 new StringSink(encoded)) // HexEncoder
		);										  // StringSource
		wcout << "iv: " << string_to_wstring(encoded) << endl;
		try
		{
			CTR_Mode<DES>::Encryption e;
			e.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s1(plain, true,
							new StreamTransformationFilter(e,
														   new StringSink(cipher)) // StreamTransformationFilter
			);																	   // StringSource
			CTR_Mode<DES>::Decryption d;
			d.SetKeyWithIV(the_key, sizeof(the_key), iv);
			StringSource s2(cipher, true,
							new StreamTransformationFilter(d,
														   new StringSink(recovered)) // StreamTransformationFilter
			);																		  // StringSource
		}
		catch (const CryptoPP::Exception &e)
		{
			cerr << e.what() << endl;
			exit(1);
		}
		break;
	}
	// case 6:
	// {
	// 	XTS<DES>::Encryption e;
	// 	CryptoPP::byte the_key[e.DefaultKeyLength()];
	// 	std::copy(key + 0, key + e.DefaultKeyLength(), the_key);
	// 	// Pretty print key
	// 	encoded.clear();
	// 	StringSource(the_key, sizeof(the_key), true,
	// 				 new HexEncoder(
	// 					 new StringSink(encoded)) // HexEncoder
	// 	);										  // StringSource
	// 	wcout << "key: " << string_to_wstring(encoded) << endl;
	// 	// Pretty print IV
	// 	encoded.clear();
	// 	StringSource(iv, sizeof(iv), true,
	// 				 new HexEncoder(
	// 					 new StringSink(encoded)) // HexEncoder
	// 	);										  // StringSource
	// 	wcout << "iv: " << string_to_wstring(encoded) << endl;
	// 	try
	// 	{
	// 		e.SetKeyWithIV(the_key, sizeof(the_key), iv);
	// 		StringSource s1(plain, true,
	// 						new StreamTransformationFilter(e,
	// 													   new StringSink(cipher), StreamTransformationFilter::DEFAULT_PADDING) // StreamTransformationFilter
	// 		);
	// 		XTS<DES>::Decryption d;
	// 		d.SetKeyWithIV(the_key, sizeof(the_key), iv);
	// 		StringSource s2(cipher, true,
	// 						new StreamTransformationFilter(d,
	// 													   new StringSink(recovered), StreamTransformationFilter::DEFAULT_PADDING) // StreamTransformationFilter
	// 		);																												  // StringSource
	// 	}
	// 	catch (const CryptoPP::Exception &e)
	// 	{
	// 		cerr << e.what() << endl;
	// 		exit(1);
	// 	}
	// 	break;
	// }
	// case 7:
	// {
	// 	CryptoPP::byte the_key[DES::DEFAULT_KEYLENGTH];
	// 	std::copy(key + 0, key + DES::DEFAULT_KEYLENGTH, the_key);
	// 	// { 7, 8, 9, 10, 11, 12, 13 }
	// 	int iv_size_num[7] = {7, 8, 9, 10, 11, 12, 13};
	// 	int iv_size_random_index = rand() % 7;
	// 	int iv_size = iv_size_num[iv_size_random_index];
	// 	byte ccm_iv[iv_size];
	// 	std::copy(iv + 0, iv + iv_size - 1, ccm_iv);
	// 	// const tag_size
	// 	const int TAG_SIZE = 8;
	// 	// TAG_SIZE = tag_size_num[tag_size_random_index];
	// 	// Pretty print key
	// 	encoded.clear();
	// 	StringSource(the_key, sizeof(the_key), true,
	// 				 new HexEncoder(
	// 					 new StringSink(encoded)) // HexEncoder
	// 	);										  // StringSource
	// 	wcout << "key: " << string_to_wstring(encoded) << endl;
	// 	// Pretty print IV
	// 	encoded.clear();
	// 	StringSource(iv, sizeof(iv), true,
	// 				 new HexEncoder(
	// 					 new StringSink(encoded)) // HexEncoder
	// 	);										  // StringSource
	// 	wcout << "iv: " << string_to_wstring(encoded) << endl;
	// 	try
	// 	{
	// 		CCM<DES, TAG_SIZE>::Encryption e;
	// 		e.SetKeyWithIV(the_key, sizeof(the_key), ccm_iv, sizeof(ccm_iv));
	// 		e.SpecifyDataLengths(0, plain.size(), 0);
	// 		StringSource s1(plain, true,
	// 						new AuthenticatedEncryptionFilter(e,
	// 														  new StringSink(cipher)) // StreamTransformationFilter
	// 		);
	// 		CCM<DES, TAG_SIZE>::Decryption d;
	// 		d.SetKeyWithIV(the_key, sizeof(the_key), ccm_iv, sizeof(ccm_iv));
	// 		d.SpecifyDataLengths(0, cipher.size() - TAG_SIZE, 0);
	// 		StringSource s2(cipher, true,
	// 						new AuthenticatedDecryptionFilter(d,
	// 														  new StringSink(recovered)) // StreamTransformationFilter
	// 		);																			 // StringSource
	// 	}
	// 	catch (const CryptoPP::Exception &e)
	// 	{
	// 		cerr << e.what() << endl;
	// 		exit(1);
	// 	}
	// 	break;
	// }
	// case 8:
	// {
	// 	CryptoPP::byte the_key[DES::DEFAULT_KEYLENGTH];
	// 	std::copy(key + 0, key + DES::DEFAULT_KEYLENGTH, the_key);

    //     byte the_iv[DES::BLOCKSIZE];
    //     std::copy(iv + 0, iv + DES::BLOCKSIZE, the_iv);
	// 	// Pretty print key
	// 	encoded.clear();
	// 	StringSource(the_key, sizeof(the_key), true,
	// 				 new HexEncoder(
	// 					 new StringSink(encoded)) // HexEncoder
	// 	);										  // StringSource
	// 	wcout << "key: " << string_to_wstring(encoded) << endl;
	// 	// Pretty print IV
	// 	encoded.clear();
	// 	StringSource(iv, sizeof(iv), true,
	// 				 new HexEncoder(
	// 					 new StringSink(encoded)) // HexEncoder
	// 	);										  // StringSource
	// 	wcout << "iv: " << string_to_wstring(encoded) << endl;
	// 	try
	// 	{
	// 		GCM<DES>::Encryption e;
	// 		e.SetKeyWithIV(the_key, sizeof(the_key), the_iv, sizeof(the_iv));
	// 		StringSource s1(plain, true,
	// 						new AuthenticatedEncryptionFilter(e,
	// 														  new StringSink(cipher)) // StreamTransformationFilter
	// 		);
	// 		GCM<DES>::Decryption d;
	// 		d.SetKeyWithIV(the_key, sizeof(the_key), the_iv, sizeof(the_iv));
	// 		StringSource s2(cipher, true,
	// 						new AuthenticatedDecryptionFilter(d,
	// 														  new StringSink(recovered)) // StreamTransformationFilter
	// 		);																			 // StringSource
	// 	}
	// 	catch (const CryptoPP::Exception &e)
	// 	{
	// 		cerr << e.what() << endl;
	// 		exit(1);
	// 	}
	// 	break;
	// }
	default:
	{
		break;
	}
	}
	//OUTPUT
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;
	wcout << "Recovered text: " << string_to_wstring(recovered) << endl;

	return 0;
}

/* Function Definitions */
/* convert wstring to string */
string wstring_to_string(const wstring &str)
{
	wstring_convert<codecvt_utf8<wchar_t>> tostring;
	return tostring.to_bytes(str);
}
/* convert string to wstring */
wstring string_to_wstring(const string &str)
{
	wstring_convert<codecvt_utf8<wchar_t>> towstring;
	return towstring.from_bytes(str);
}
