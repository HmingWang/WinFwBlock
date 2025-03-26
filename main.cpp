#include <windows.h>
#include <netfw.h>
#include <comdef.h>
#include <stdio.h>
#include <string>
#include <stdexcept>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

class FirewallRuleEditor
{
public:
    FirewallRuleEditor()
    {
        HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        if (FAILED(hr))
            throw std::runtime_error("COM initialization failed");

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

    ~FirewallRuleEditor()
    {
        if (m_pPolicy)
            m_pPolicy->Release();
        CoUninitialize();
    }

    // ��ȡ�������
    bool GetRule(const std::wstring &ruleName, INetFwRule **ppRule)
    {
        INetFwRules *pRules = NULL;
        HRESULT hr = m_pPolicy->get_Rules(&pRules);
        if (FAILED(hr))
            return false;

        hr = pRules->Item(_bstr_t(ruleName.c_str()), ppRule);
        pRules->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ�������
    bool SetRuleDescription(const std::wstring &ruleName, const std::wstring &description)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_Description(_bstr_t(description.c_str()));
        pRule->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ���˿�
    bool SetRulePorts(const std::wstring &ruleName, const std::wstring &localPorts)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_LocalPorts(_bstr_t(localPorts.c_str()));
        pRule->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ�����
    bool SetRuleAction(const std::wstring &ruleName, bool allow)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_Action(allow ? NET_FW_ACTION_ALLOW : NET_FW_ACTION_BLOCK);
        pRule->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ�������״̬
    bool SetRuleEnabled(const std::wstring &ruleName, bool enabled)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_Enabled(enabled ? VARIANT_TRUE : VARIANT_FALSE);
        pRule->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ�����
    bool SetRuleDirection(const std::wstring &ruleName, bool inbound)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_Direction(
            inbound ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT);
        pRule->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ���Ӧ�ó���·��
    bool SetRuleApplication(const std::wstring &ruleName, const std::wstring &appPath)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_ApplicationName(_bstr_t(appPath.c_str()));
        pRule->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ���Э��
    bool SetRuleProtocol(const std::wstring &ruleName, long protocol)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_Protocol(protocol);
        pRule->Release();

        return SUCCEEDED(hr);
    }

    // �޸Ĺ���Զ�̵�ַ
    bool SetRuleRemoteAddresses(const std::wstring &ruleName, const std::wstring &remoteAddrs)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
            return false;

        HRESULT hr = pRule->put_RemoteAddresses(_bstr_t(remoteAddrs.c_str()));
        pRule->Release();

        if( SUCCEEDED(hr)){
            printf("Set remote address success\n");
            return true;
        }
        else{
            printf("Set remote address failed\n");
            return false;
        }
    }

    // ��ӡ������Ϣ
    void PrintRuleInfo(const std::wstring &ruleName)
    {
        INetFwRule *pRule = NULL;
        if (!GetRule(ruleName, &pRule))
        {
            printf("Rule '%ws' not found\n", ruleName.c_str());
            return;
        }

        BSTR name, desc, app, localPorts, remoteAddrs;
        LONG protocol;
        NET_FW_ACTION action;
        NET_FW_RULE_DIRECTION direction;
        VARIANT_BOOL enabled;

        pRule->get_Name(&name);
        pRule->get_Description(&desc);
        pRule->get_ApplicationName(&app);
        pRule->get_LocalPorts(&localPorts);
        pRule->get_RemoteAddresses(&remoteAddrs);
        pRule->get_Protocol(&protocol);
        pRule->get_Action(&action);
        pRule->get_Direction(&direction);
        pRule->get_Enabled(&enabled);

        printf("\n[Rule: %ws]\n", name);
        printf("  Description: %ws\n", desc ? desc : L"");
        printf("  Application: %ws\n", app ? app : L"");
        printf("  Local Ports: %ws\n", localPorts ? localPorts : L"");
        printf("  Remote Addresses: %ws\n", remoteAddrs ? remoteAddrs : L"");
        printf("  Protocol: %ws\n", GetProtocolText(protocol));
        printf("  Action: %s\n", action == NET_FW_ACTION_ALLOW ? "Allow" : "Block");
        printf("  Direction: %s\n", direction == NET_FW_RULE_DIR_IN ? "Inbound" : "Outbound");
        printf("  Enabled: %s\n", enabled == VARIANT_TRUE ? "Yes" : "No");

        SysFreeString(name);
        SysFreeString(desc);
        SysFreeString(app);
        SysFreeString(localPorts);
        SysFreeString(remoteAddrs);
        // SysFreeString(protocol);
        pRule->Release();
    }

private:
    INetFwPolicy2 *m_pPolicy = NULL;

    const wchar_t *GetProtocolText(LONG protocol)
    {
        switch (protocol)
        {
        case NET_FW_IP_PROTOCOL_TCP:
            return L"TCP";
        case NET_FW_IP_PROTOCOL_UDP:
            return L"UDP";
        case NET_FW_IP_PROTOCOL_ANY:
            return L"Any";
        default:
            return L"Other";
        }
    }
};

bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    
    // ���䲢��ʼ��SID
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup)) {
        return false;
    }
    
    // ������Ƴ�Ա�ʸ�
    if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
        isAdmin = FALSE;
    }
    
    FreeSid(adminGroup);
    return isAdmin == TRUE;
}

void ElevateNow() {
    CHAR szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {
        // ʹ��ShellExecute�Թ���ԱȨ����������
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        
        if (!ShellExecuteEx(&sei)) {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED) {
                printf("�û��ܾ���UAC��������\n");
            }
        }
        exit(0); // �˳���ǰʵ��
    }
}
int main()
{

    // ����Ƿ��Ѿ��ǹ���ԱȨ��
    if (!IsRunAsAdmin()) {
        printf("��Ҫ����ԱȨ�ޣ�������������...\n");
        ElevateNow();
    } else {
        printf("�Ѿ��й���ԱȨ��\n");
    }

    try
    {
        FirewallRuleEditor editor;
        std::wstring ruleName = L"!IP_Block";

        // ��ӡ�޸�ǰ�Ĺ�����Ϣ
        printf("Before modification:\n");
        editor.PrintRuleInfo(ruleName);

        bool success = true;
        // �޸Ĺ�������
        success &= editor.SetRuleDescription(ruleName, L"Updated application rule");
        // editor.SetRulePorts(ruleName, L"8080,8081");
        // editor.SetRuleAction(ruleName, true); // Allow
        // editor.SetRuleEnabled(ruleName, true);
        // editor.SetRuleDirection(ruleName, true); // Inbound
        success &= editor.SetRuleRemoteAddresses(ruleName, L"192.168.1.1,192.168.1.2");

        if (success)
        {
            // ��ӡ�޸ĺ�Ĺ�����Ϣ
            printf("\nAfter modification:\n");
            editor.PrintRuleInfo(ruleName);
        }
        else
        {
            printf("Failed to modify rule\n");
        }
    }
    catch (const std::exception &e)
    {
        printf("Error: %s\n", e.what());
        return 1;
    }

    system("pause");
    return 0;
}