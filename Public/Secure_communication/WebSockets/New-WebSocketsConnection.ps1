function New-WebSocketsConnection {
    <#
    .SYNOPSIS
        createS a WebSockets connection.
    .DESCRIPTION
        This function takes a URI as a parameter and creates a new ClientWebSocket object using the New-Object cmdlet.
        It then calls the ConnectAsync method on the ClientWebSocket object to establish a connection to the specified URI.
        Finally, it returns the ClientWebSocket object, which you can use to send and receive data over the WebSockets connection.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        https://github.com/alainQtec/CipherTron/blob/main/Public/Secure_communication/WebSockets/New-WebSocketsConnection.ps1
    .EXAMPLE
        $connection = New-WebSocketsConnection -Uri "wss://example.com/websockets"
        creates a new WebSockets connection to the specified URI and stores the connection in the $connection variable. You can then use the ClientWebSocket object's methods to send and receive data over the connection.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Net.WebSockets.ClientWebSocket])]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$Uri
    )

    begin {
        # Create a new WebSockets client
        $client = New-Object System.Net.WebSockets.ClientWebSocket
    }
    Process {
        if ($PSCmdlet.ShouldProcess("Connect to the URI $Uri", "", "")) {
            $client.ConnectAsync($Uri, [System.Threading.CancellationToken]::None).Wait()
        }
    }
    end {
        # Return the WebSockets client
        $client
    }
}
