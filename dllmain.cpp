#include "blabla/include.h"
#include "driver/driver.h"
#include "blabla/skStr.h"
#include <locale>
#include <codecvt>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
#pragma optimize("", off)
using namespace std;
namespace fs = std::filesystem;


bool DllMain(HMODULE Module, DWORD CallReason, LPVOID Reserved)
{
    if (CallReason == DLL_PROCESS_ATTACH)
    {
        if (kcvh::knzfnddruv()) {
            system("cls");
        }
        else
        {
            int result = MessageBox(NULL, L"Driver not Found!", L"Driver", MB_ICONINFORMATION | MB_OK);
            if (result == IDOK)
            {
                return -1;
            }
        }
        if (kcvh::kcprfnd(L"WarriorZ.exe")) {
            kschltygf = get_guarded();
            check::guard = kschltygf;
            base = kcvh::kscvhimdh();
            system("cls");
            ebrugundes::codexocomebakc();
        }
        else {
            system("cls");
            system("color c");
            std::cout << "Kaos -> Game Not Found!";
            Sleep(2000);
            exit(0);
        }
    }
}

#pragma optimize("", on)
