function Send-WebSocketsMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Net.WebSockets.ClientWebSocket]
        $Connection,

        [Parameter(Mandatory = $true)]
        [String]
        $Text
    )

    # Create a buffer for the message
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($Text)

    # Send the message over the WebSockets connection
    $Connection.SendAsync(
        $buffer,
        [System.Net.WebSockets.WebSocketMessageType]::Text,
        $true,
        [System.Threading.CancellationToken]::None
    ).Wait()
}
