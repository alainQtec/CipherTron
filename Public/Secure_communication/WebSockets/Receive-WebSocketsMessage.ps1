function Receive-WebSocketsMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Net.WebSockets.ClientWebSocket]
        $Connection
    )

    # Create a buffer to receive the message
    $buffer = New-Object System.Byte[] 1024

    # Receive the message from the WebSockets connection
    $result = $Connection.ReceiveAsync(
        $buffer,
        [System.Threading.CancellationToken]::None
    ).Result

    # Return the message as a string
    [System.Text.Encoding]::UTF8.GetString($buffer[0..($result.Count - 1)])
}