#include <windows.h>
#include <netfw.h>
#include <comdef.h>
#include <stdio.h>
#include <stdexcept>
#pragma comment(lib, "ole32.lib")

class FirewallRuleReader
{
public:
    FirewallRuleReader()
    {
        HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        if (FAILED(hr))
        {
            throw std::runtime_error("COM initialization failed");
        }

        hr = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            (void **)&m_pPolicy);

        if (FAILED(hr))
        {
            CoUninitialize();
            throw std::runtime_error("Failed to create firewall policy instance");
        }
    }

    ~FirewallRuleReader()
    {
        if (m_pPolicy)
            m_pPolicy->Release();
        CoUninitialize();
    }

    void PrintAllRules()
    {
        INetFwRules *pRules = NULL;
        HRESULT hr = m_pPolicy->get_Rules(&pRules);
        if (FAILED(hr))
            return;

        long count = 0;
        pRules->get_Count(&count);
        printf("Total firewall rules: %d\n", count);

        IUnknown *pEnumerator = NULL;
        IEnumVARIANT *pEnumVariant = NULL;

        hr = pRules->get__NewEnum(&pEnumerator);
        if (SUCCEEDED(hr))
        {
            hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void **)&pEnumVariant);
        }

        if (SUCCEEDED(hr))
        {
            VARIANT var;
            VariantInit(&var);

            while (pEnumVariant->Next(1, &var, NULL) == S_OK)
            {
                INetFwRule *pRule = NULL;

                if (SUCCEEDED(V_DISPATCH(&var)->QueryInterface(__uuidof(INetFwRule), (void **)&pRule)))
                {
                    PrintRuleDetails(pRule);
                    pRule->Release();
                }
                VariantClear(&var);
            }
            pEnumVariant->Release();
        }
        pRules->Release();
    }

    bool FindRuleByName(const std::wstring &ruleName, INetFwRule **ppRule = nullptr)
    {
        INetFwRules *pRules = NULL;
        HRESULT hr = m_pPolicy->get_Rules(&pRules);
        if (FAILED(hr))
            return false;

        bool found = false;
        IUnknown *pEnumerator = NULL;
        IEnumVARIANT *pEnumVariant = NULL;

        hr = pRules->get__NewEnum(&pEnumerator);
        if (SUCCEEDED(hr))
        {
            hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void **)&pEnumVariant);
        }

        if (SUCCEEDED(hr))
        {
            VARIANT var;
            VariantInit(&var);

            while (pEnumVariant->Next(1, &var, NULL) == S_OK && !found)
            {
                INetFwRule *pRule = NULL;

                if (SUCCEEDED(V_DISPATCH(&var)->QueryInterface(__uuidof(INetFwRule), (void **)&pRule)))
                {
                    BSTR bstrName = NULL;
                    pRule->get_Name(&bstrName);

                    if (bstrName && _wcsicmp(bstrName, ruleName.c_str()) == 0)
                    {
                        found = true;
                        if (ppRule)
                        {
                            *ppRule = pRule;
                            (*ppRule)->AddRef(); // 增加引用计数以便外部使用
                        }
                    }

                    SysFreeString(bstrName);
                    if (!found)
                        pRule->Release();
                }
                VariantClear(&var);
            }
            pEnumVariant->Release();
        }

        pRules->Release();
        return found;
    }
    void PrintRuleDetails(INetFwRule *pRule)
    {
        BSTR name, desc, app, localPorts, remoteAddrs;
        NET_FW_ACTION action;
        NET_FW_RULE_DIRECTION direction;
        VARIANT_BOOL enabled;

        pRule->get_Name(&name);
        pRule->get_Description(&desc);
        pRule->get_ApplicationName(&app);
        pRule->get_LocalPorts(&localPorts);
        pRule->get_RemoteAddresses(&remoteAddrs);
        pRule->get_Action(&action);
        pRule->get_Direction(&direction);
        pRule->get_Enabled(&enabled);

        printf("\n[Rule] %ws\n", name ? name : L"");
        printf("  Description: %ws\n", desc ? desc : L"");
        printf("  Application: %ws\n", app ? app : L"");
        printf("  Local Ports: %ws\n", localPorts ? localPorts : L"Any");
        printf("  Remote Addresses: %ws\n", remoteAddrs ? remoteAddrs : L"Any");
        printf("  Action: %s\n", action == NET_FW_ACTION_ALLOW ? "Allow" : "Block");
        printf("  Direction: %s\n", direction == NET_FW_RULE_DIR_IN ? "Inbound" : "Outbound");
        printf("  Enabled: %s\n", enabled == VARIANT_TRUE ? "Yes" : "No");

        SysFreeString(name);
        SysFreeString(desc);
        SysFreeString(app);
        SysFreeString(localPorts);
        SysFreeString(remoteAddrs);
    }

private:
    INetFwPolicy2 *m_pPolicy = NULL;
};

int main()
{
    try
    {
        FirewallRuleReader reader;
        INetFwRule *pRule = NULL;
        if (reader.FindRuleByName(L"！IP黑名单", &pRule))
        {
            printf("Found exact match:\n");
            reader.PrintRuleDetails(pRule);
            pRule->Release();
        }
        else
        {
            printf("No exact match found.\n");
        }
    }
    catch (const std::exception &e)
    {
        printf("Error: %s\n", e.what());
        return 1;
    }
    return 0;
}