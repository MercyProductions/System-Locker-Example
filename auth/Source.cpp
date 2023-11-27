#include <iostream>
#include "Windows.h"
#include <string>

#include <sddl.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment (lib, "Normaliz.lib")
#pragma comment (lib, "Wldap32.lib")
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "crypt32.lib")

#define CURL_STATICLIB

#include "curl/curl.h"

#pragma comment (lib, "curl/libcurl_a.lib")

std::string username, password, KEY, systemID, versionNUM, uwu, IPAddy, WindowSID;


void log(const char* msg)
{
	std::cout << msg << "\n";
}

uintptr_t bytes;

uintptr_t get_total_physical_memory() 
{
	MEMORYSTATUSEX status;
	status.dwLength = sizeof(status);

	if (GlobalMemoryStatusEx(&status)) {
		uintptr_t bytes = status.ullTotalPhys;
		return bytes;
	}
	else 
	{
		std::cerr << "GlobalMemoryStatusEx failed. Error: " << GetLastError() << std::endl;
		return 0; 
	}
}

static size_t my_write(void* buffer, size_t size, size_t nmemb, void* param) 
{
	std::string& text = *static_cast<std::string*>(param);
	size_t totalsize = size * nmemb;

	if (totalsize == 0 || buffer == nullptr) 
	{
		return 0;
	}

	try 
	{
		text.append(static_cast<char*>(buffer), totalsize);
	}
	catch (const std::bad_alloc& ex) 
	{
		std::cerr << "Failed to allocate memory for data. " << ex.what() << std::endl;
		return 0;
	}

	return totalsize;
}


#pragma region Branding

void Branding()
{
	std::string asciiArt =
		"   _______     _______ _______ ______ __  __   _      ____   _____ _  ________ _____  \n"
		"  / ____\\ \\   / / ____|__   __|  ____|  \\/  | | |    / __ \\ / ____| |/ /  ____|  __ \\ \n"
		" | (___  \\ \\_/ / (___    | |  | |__  | \\  / | | |   | |  | | |    | ' /| |__  | |__) |\n"
		"  \\___ \\  \\   / \\___ \\   | |  |  __| | |\\/| | | |   | |  | | |    |  < |  __| |  _  / \n"
		"  ____) |  | |  ____) |  | |  | |____| |  | | | |___| |__| | |____| . \\| |____| | \\ \\ \n"
		" |_____/   |_| |_____/   |_|  |______|_|  |_| |______\\____/ \\_____|_|\\_\\______|_|  \\_\\ \n";

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
	std::cout << asciiArt;
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

#pragma endregion

#pragma region IPAddy

std::string GetIPAddress()
{
	std::string ip_address;
	const char* command;

#ifdef _WIN32
	command = "ipconfig";
#else
	command = "ifconfig";
#endif

	FILE* pipe = _popen(command, "r");

	if (!pipe) {
		return "Failed to run the command.";
	}

	char buffer[128];
	bool foundIPAddress = false;

	while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
		if ((strstr(buffer, "IPv4 Address") != nullptr) || (strstr(buffer, "inet") != nullptr)) {
			ip_address = buffer;
			foundIPAddress = true;
			break;
		}
	}

	_pclose(pipe);

	if (foundIPAddress) {
		std::size_t start = ip_address.find_first_of("0123456789.");
		if (start != std::string::npos) {
			std::size_t end = ip_address.find_last_of("0123456789.");
			if (end != std::string::npos) {
				ip_address = ip_address.substr(start, end - start + 1);
				return ip_address;
			}
		}

		return "Failed to extract IP address.";
	}
	else {
		return "Failed to retrieve IP address.";
	}
}

#pragma endregion

#pragma region WindowsUserSID

bool GetCurrentUserSID(std::wstring& userSID) {
	// Get the current user's token
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl;
		return false;
	}

	// Get the length of the user's SID
	DWORD dwLength = 0;
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);

	if (dwLength == 0) {
		std::cerr << "GetTokenInformation failed. Error: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return false;
	}

	// Allocate memory for the SID
	PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(new BYTE[dwLength]);

	// Retrieve the user's SID
	if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
		// Convert the SID to a string
		LPWSTR sidString = nullptr;
		if (ConvertSidToStringSidW(pTokenUser->User.Sid, &sidString)) {
			userSID = sidString;
			LocalFree(sidString);
		}
		else {
			std::cerr << "ConvertSidToStringSidW failed. Error: " << GetLastError() << std::endl;
		}
	}
	else {
		std::cerr << "GetTokenInformation failed. Error: " << GetLastError() << std::endl;
	}

	// Clean up
	delete[] reinterpret_cast<BYTE*>(pTokenUser);
	CloseHandle(hToken);

	return true;
}


#pragma endregion


void LoginLogged()
{
	CURL* curl;
	CURLcode res;

	// Your Discord webhook URL
	std::string webhookUrl = "https://discord.com/api/webhooks/1170586574463971369/24JwZsrGrmH0LaKYBp1G2HZ39xo3FNHGvhGO3iIgyGi58_5jB6iY58UEtle0euahCRk6";

	// Strings for your message
	std::string title = "USER LOGGED IN!";
	std::string LoggedIP = "IP Addy: " + IPAddy; // Replace with your IP
	std::string LoggedSID = "SID: " + WindowSID; // Replace with your SID
	std::string LoggedLicenseKey = "LICENSE KEY: " + KEY; // Replace with your License Key

	// Construct the JSON message manually
	std::string message = "{";
	message += "\"content\": null,";
	message += "\"embeds\": [";
	message += "{";
	message += "\"title\": \"" + title + "\",";
	message += "\"description\": \"" + LoggedIP + "\\n" + LoggedSID + "\\n" + LoggedLicenseKey + "\",";
	message += "\"color\": 16711680";
	message += "}";
	message += "],";
	message += "\"attachments\": []";
	message += "}";

	curl = curl_easy_init();
	if (curl) {
		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_URL, webhookUrl.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, message.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, message.length());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// Perform the POST request
		res = curl_easy_perform(curl);

		if (res != CURLE_OK) {
			std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
		}
		else {
			long response_code;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

			if (response_code == 204) {
				std::cout << "Message sent successfully to Discord webhook!" << std::endl;
			}
			else {
				std::cerr << "Failed to send the message. HTTP Response Code: " << response_code << std::endl;
			}
		}

		curl_easy_cleanup(curl);
	}
	else {
		std::cerr << "Failed to initialize libcurl." << std::endl;
	}

}

int main()
{
	static int LoginType;
	int choice;

	Branding();

	std::cout << "\n [1] Login With User Information. \n [2] License key only\n\n Choose option: ";
	std::cin >> choice;

	switch (choice) 
	{
		case 1:
		log("\n\nEnter your username");
		std::cin >> username;
		log("Insert your password");
		std::cin >> password;
		log("\nInsert your Key");
		std::cin >> KEY;
		break;
		case 2:
		log("\nInsert your Key");
		std::cin >> KEY;
		break;
		default:
		std::cout << "Invalid choice. Please choose a valid option (1 or 2)." << std::endl;
	}

	LoginType = choice;

	#pragma region MultiLoader
	if (KEY.find("WZ-Chair") != std::string::npos)
	{
		systemID = "&system=2f21c713b4307ded3ac0&hwid=";
		versionNUM = "&version=3";
	}

	else 
	{
		if (KEY.find("Master") != std::string::npos)
		{
			systemID = "&system=47be9453b54895399332&hwid=";
			versionNUM = "&version=0";
		}
	}
	#pragma endregion

	using namespace std;
	std::string result;
	CURL* curl;
	CURLcode res;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) 
	{
		std::cerr << "Failed to initialize libcurl globally." << std::endl;
	}

	curl = curl_easy_init();
	if (!curl) 
	{
		std::cerr << "Failed to initialize libcurl." << std::endl;
		curl_global_cleanup();
	}

		if (curl) 
		{
			if (LoginType == 1) 
			{
				uwu = "https://systemlocker.net/auth.php?username="
					+ username
					+ "&password="
					+ password
					+ systemID
					+ std::to_string(get_total_physical_memory())
					+ versionNUM;

				curl_easy_setopt(curl, CURLOPT_URL, uwu.c_str()); curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_write); curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result); res = curl_easy_perform(curl);

				curl_easy_cleanup(curl);

				if (CURLE_OK != res) {
					std::cerr << "CURL error: " << res << '\n';
					curl_easy_cleanup(curl);
					curl_global_cleanup();
				}
			}

			else if (LoginType == 2) 
			{
				uwu = "https://systemlocker.net/mikros.php?key="
					+ KEY
					+ systemID
					+ std::to_string(get_total_physical_memory())
					+ versionNUM;

				curl_easy_setopt(curl, CURLOPT_URL, uwu.c_str()); curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_write); curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result); res = curl_easy_perform(curl);

				curl_easy_cleanup(curl);

				if (CURLE_OK != res) {
					std::cerr << "CURL error: " << res << '\n';
					getchar();
				}
			}
		}

		curl_global_cleanup();

		#pragma region ResponseHandling
		if (!strcmp(result.c_str(), "true"))
		{
			system("CLS");
			Branding();

			std::cout << "\nLogged In!" << std::endl;

			if (LoginType == 1)
			{
				std::cout << "Username : \n" << username << std::endl;
			}
			else if (LoginType == 2)
			{
				std::cout << "License Key: " << KEY << std::endl;
			}

			IPAddy = GetIPAddress();
			std::cout << "IP Address: " << IPAddy << std::endl;

			std::wstring UserSID;
			if (GetCurrentUserSID(UserSID)) {
				std::wcout << L"Current User SID: " << UserSID << std::endl;
				// If you need to convert it to a std::string, you can do so
				std::string SID(UserSID.begin(), UserSID.end());
				std::cout << "Current User SID (std::string): " << SID << std::endl;
				WindowSID = SID;
			}
			else {
				std::cerr << "Failed to retrieve the current user's SID." << std::endl;
			}

			uint64_t totalMemory = get_total_physical_memory();
			std::cout << "Total Physical Memory: " << std::to_string(totalMemory) << " bytes" << std::endl;
			//
			LoginLogged();
			//
			std::cout << "Press Enter to exit..." << std::endl;
			std::cin.get();
		}
		else if (!strcmp(result.c_str(), "false"))
		{
			std::cout << "Error Logging In";
		}
		else if (!strcmp(result.c_str(), "no u/p"))
		{
			std::cout << "No Username Or Password Inputted";
		}
		else if (!strcmp(result.c_str(), "no sys"))
		{
			std::cout << "Invalid HTTP Request";
		}
		else if (!strcmp(result.c_str(), "not verified"))
		{
			std::cout << "Account Does Not Own Menu.";
		}
		else if (!strcmp(result.c_str(), "bad u/p"))
		{
			std::cout << "Invalid Username Or Password";
		}
		else if (!strcmp(result.c_str(), "bad keys"))
		{
			std::cout << "Invalid License Key.";
		}
		else if (!strcmp(result.c_str(), "expired key"))
		{
			std::cout << "Your Key Is Expired";
		}
		else if (!strcmp(result.c_str(), "frozen"))
		{
			std::cout << "Account Is Frozen";
		}
		else if (!strcmp(result.c_str(), "hwid"))
		{
			std::cout << "Invalid HWID";
		}
		else if (!strcmp(result.c_str(), "spoofsuspected"))
		{
			std::cout << "HWID Spoofing Suspected";
		}
		else if (!strcmp(result.c_str(), "outdated"))
		{
			std::cout << "Menu Version Outdated";
		}
		else if (!strcmp(result.c_str(), "dbe"))
		{
			std::cout << "Internal Auth Server Error";
		}
		else
		{
			std::cout << "Unknown Error" << std::endl;
			std::cout << "Press Enter to exit..." << std::endl;
			std::cin.get();
			return 0;
		}
		#pragma endregion
		std::cin.get();
		getchar();
}
