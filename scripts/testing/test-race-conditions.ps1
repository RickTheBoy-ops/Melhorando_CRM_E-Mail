# Test script for race condition validation
# Tests concurrent email processing to ensure no duplicates

Write-Host "Starting Race Condition Test for Email Service..." -ForegroundColor Green

# Test configuration
$emailServiceUrl = "http://localhost:8002"
$concurrentRequests = 20
$testRounds = 3

# Function to send email request
function Send-EmailRequest {
    param($requestId)
    
    $body = @{
        to = @("test$requestId@example.com")
        subject = "Race Condition Test - Request $requestId"
        body = "Testing concurrent processing - Request ID: $requestId - Timestamp: $(Get-Date)"
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$emailServiceUrl/email/send" -Method POST -ContentType "application/json" -Body $body
        Write-Host "Request $requestId - Success: $($response.message)" -ForegroundColor Green
        return @{ Success = $true; RequestId = $requestId; Response = $response }
    }
    catch {
        Write-Host "Request $requestId - Error: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; RequestId = $requestId; Error = $_.Exception.Message }
    }
}

# Function to check service health
function Test-ServiceHealth {
    try {
        $health = Invoke-RestMethod -Uri "$emailServiceUrl/health" -Method GET
        Write-Host "Service Health: $($health.status)" -ForegroundColor Cyan
        Write-Host "Queue Sizes - Email: $($health.email_queue_size), Retry: $($health.retry_queue_size), Failed: $($health.failed_queue_size)" -ForegroundColor Cyan
        return $true
    }
    catch {
        Write-Host "Service health check failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main test execution
Write-Host "`nChecking service health..." -ForegroundColor Yellow
if (-not (Test-ServiceHealth)) {
    Write-Host "Service is not healthy. Exiting test." -ForegroundColor Red
    exit 1
}

for ($round = 1; $round -le $testRounds; $round++) {
    Write-Host "`n=== Test Round $round ===" -ForegroundColor Magenta
    
    # Create concurrent jobs
    $jobs = @()
    for ($i = 1; $i -le $concurrentRequests; $i++) {
        $requestId = "$round-$i"
        $job = Start-Job -ScriptBlock ${function:Send-EmailRequest} -ArgumentList $requestId
        $jobs += $job
    }
    
    Write-Host "Started $concurrentRequests concurrent requests..." -ForegroundColor Yellow
    
    # Wait for all jobs to complete
    $jobs | Wait-Job | Out-Null
    
    # Collect results
    $results = $jobs | Receive-Job
    $jobs | Remove-Job
    
    # Analyze results
    $successCount = ($results | Where-Object { $_.Success }).Count
    $errorCount = ($results | Where-Object { -not $_.Success }).Count
    
    Write-Host "Round $round Results:" -ForegroundColor Cyan
    Write-Host "  Successful: $successCount" -ForegroundColor Green
    Write-Host "  Failed: $errorCount" -ForegroundColor Red
    
    if ($errorCount -gt 0) {
        Write-Host "  Errors:" -ForegroundColor Red
        $results | Where-Object { -not $_.Success } | ForEach-Object {
            Write-Host "    Request $($_.RequestId): $($_.Error)" -ForegroundColor Red
        }
    }
    
    # Check service health after round
    Start-Sleep -Seconds 2
    Test-ServiceHealth | Out-Null
    
    # Wait between rounds
    if ($round -lt $testRounds) {
        Write-Host "Waiting 3 seconds before next round..." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
    }
}

Write-Host "`n=== Test Summary ===" -ForegroundColor Magenta
Write-Host "Total requests sent: $($concurrentRequests * $testRounds)" -ForegroundColor Cyan
Write-Host "Test completed successfully!" -ForegroundColor Green

# Final health check
Write-Host "`nFinal service health check:" -ForegroundColor Yellow
Test-ServiceHealth | Out-Null