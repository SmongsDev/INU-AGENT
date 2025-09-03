#!/usr/bin/env python3

import json
import time
from cloudtrail_threat_detector import CloudTrailThreatDetector


def create_sample_cloudtrail_logs():
    """Create sample CloudTrail logs for testing."""
    
    # Normal S3 access from console
    normal_log_1 = {
        "eventTime": "2024-01-15T10:30:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "awsRegion": "us-east-1",
        "readOnly": True,
        "managementEvent": False,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "john.doe",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
        },
        "sourceIPAddress": "203.0.113.12",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "requestParameters": {
            "bucketName": "prod-data-bucket"
        }
    }
    
    # Suspicious Red Team tool usage
    threat_log_1 = {
        "eventTime": "2024-01-15T02:15:00Z",
        "eventSource": "s3.amazonaws.com", 
        "eventName": "ListBucket",
        "awsRegion": "us-east-1",
        "readOnly": True,
        "managementEvent": False,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "test-user",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
        },
        "sourceIPAddress": "198.51.100.5",
        "userAgent": "stratus-red-team/1.0",
        "requestParameters": {
            "bucketName": "stratus-red-team-bucket"
        }
    }
    
    # Normal IAM access during business hours
    normal_log_2 = {
        "eventTime": "2024-01-15T14:20:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "ListUsers",
        "awsRegion": "us-east-1", 
        "readOnly": True,
        "managementEvent": True,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "admin",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
        },
        "sourceIPAddress": "203.0.113.15",
        "userAgent": "aws-console"
    }
    
    # Suspicious programmatic access at night with high-risk action
    threat_log_2 = {
        "eventTime": "2024-01-15T23:45:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "readOnly": False,
        "managementEvent": True,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "automation",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
        },
        "sourceIPAddress": "10.0.1.50",
        "userAgent": "aws-cli/2.0.0 Python/3.8.0",
        "requestParameters": {
            "userName": "suspicious-user"
        }
    }
    
    # Access denied on suspicious resource
    threat_log_3 = {
        "eventTime": "2024-01-15T15:30:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetBucketPolicy", 
        "awsRegion": "us-east-1",
        "readOnly": True,
        "managementEvent": False,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "external-user",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
        },
        "sourceIPAddress": "198.51.100.10",
        "userAgent": "python-requests/2.25.1",
        "errorCode": "AccessDenied",
        "requestParameters": {
            "bucketName": "test-red-team-bucket"
        }
    }
    
    # Normal EC2 operation
    normal_log_3 = {
        "eventTime": "2024-01-15T11:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-west-2",
        "readOnly": True,
        "managementEvent": True,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "devops",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
        },
        "sourceIPAddress": "203.0.113.20",
        "userAgent": "aws-console"
    }
    
    # Multiple suspicious indicators
    threat_log_4 = {
        "eventTime": "2024-01-15T01:30:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "readOnly": False,
        "managementEvent": True,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "temp-user",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
        },
        "sourceIPAddress": "192.168.1.100",
        "userAgent": "boto3/1.20.0",
        "errorCode": "UnauthorizedOperation",
        "requestParameters": {
            "userName": "elevated-user",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    }
    
    return [
        normal_log_1, threat_log_1, normal_log_2, threat_log_2,
        threat_log_3, normal_log_3, threat_log_4
    ]


def test_feature_extraction():
    """Test feature extraction functionality."""
    print("=== Testing Feature Extraction ===")
    
    detector = CloudTrailThreatDetector()
    sample_logs = create_sample_cloudtrail_logs()
    
    for i, log in enumerate(sample_logs):
        print(f"\nLog {i+1}:")
        features = detector.extract_features(log)
        print(f"Event: {log['eventName']} from {log['eventSource']}")
        print(f"Features extracted: {features.shape[1]} columns")
        print(f"Threat indicators: threat_tool={features['has_threat_tool'].iloc[0]}, "
              f"night_time={features['is_night_time'].iloc[0]}, "
              f"programmatic={features['is_programmatic'].iloc[0]}")


def test_model_training():
    """Test model training and evaluation."""
    print("\n=== Testing Model Training ===")
    
    # Create expanded sample data for training
    sample_logs = create_sample_cloudtrail_logs()
    
    # Duplicate logs to have more training data
    expanded_logs = sample_logs * 50  # 350 samples total
    
    detector = CloudTrailThreatDetector(
        n_estimators=50,  # Reduced for faster training with small dataset
        max_depth=8,
        random_state=42
    )
    
    print(f"Training on {len(expanded_logs)} log events...")
    start_time = time.time()
    
    results = detector.train(expanded_logs)
    
    training_time = time.time() - start_time
    print(f"Training completed in {training_time:.2f} seconds")
    
    return detector, results


def test_prediction_performance():
    """Test prediction performance and accuracy."""
    print("\n=== Testing Prediction Performance ===")
    
    # Train model
    detector, _ = test_model_training()
    
    # Test individual predictions
    sample_logs = create_sample_cloudtrail_logs()
    expected_results = [False, True, False, True, True, False, True]  # Expected threat classifications
    
    print("\nTesting individual predictions:")
    correct_predictions = 0
    total_predictions = len(sample_logs)
    
    for i, (log, expected) in enumerate(zip(sample_logs, expected_results)):
        start_time = time.time()
        
        # Test both prediction methods
        is_threat = detector.predict(log)
        result_with_confidence = detector.predict_with_confidence(log)
        
        prediction_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        print(f"\nLog {i+1}: {log['eventName']} from {log['eventSource']}")
        print(f"Expected: {'Threat' if expected else 'Normal'}")
        print(f"Predicted: {'Threat' if is_threat else 'Normal'}")
        print(f"Confidence: {result_with_confidence['confidence']:.3f}")
        print(f"Prediction time: {prediction_time:.2f}ms")
        
        if is_threat == expected:
            correct_predictions += 1
            print("✓ Correct")
        else:
            print("✗ Incorrect")
    
    accuracy = correct_predictions / total_predictions
    print(f"\nOverall accuracy: {accuracy:.2%} ({correct_predictions}/{total_predictions})")
    
    return detector


def test_model_persistence():
    """Test model save/load functionality."""
    print("\n=== Testing Model Persistence ===")
    
    # Train a model
    detector1, _ = test_model_training()
    
    # Save model
    model_path = "models/cloudtrail_detector.pkl"
    detector1.save_model(model_path)
    
    # Load model in new detector instance
    detector2 = CloudTrailThreatDetector()
    detector2.load_model(model_path)
    
    # Test that both models give same predictions
    sample_log = create_sample_cloudtrail_logs()[0]
    
    pred1 = detector1.predict_with_confidence(sample_log)
    pred2 = detector2.predict_with_confidence(sample_log)
    
    print(f"Original model prediction: {pred1}")
    print(f"Loaded model prediction: {pred2}")
    
    if pred1['is_threat'] == pred2['is_threat'] and abs(pred1['confidence'] - pred2['confidence']) < 0.001:
        print("✓ Model persistence test passed")
    else:
        print("✗ Model persistence test failed")


def demo_usage():
    """Demonstrate the intended usage of the detector."""
    print("\n=== Usage Demonstration ===")
    
    # Initialize and train detector
    detector = CloudTrailThreatDetector()
    sample_logs = create_sample_cloudtrail_logs() * 20  # More training data
    
    print("Training detector...")
    detector.train(sample_logs)
    
    print("\n--- Example Usage ---")
    
    # Example 1: Normal log
    normal_log = {
        "eventTime": "2024-01-15T10:30:00Z",
        "eventSource": "s3.amazonaws.com", 
        "eventName": "GetObject",
        "userIdentity": {"type": "IAMUser", "userName": "john.doe"},
        "sourceIPAddress": "203.0.113.12",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    
    # Example 2: Threat log
    threat_log = {
        "eventTime": "2024-01-15T02:15:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "ListBucket", 
        "userIdentity": {"type": "IAMUser", "userName": "test-user"},
        "sourceIPAddress": "198.51.100.5",
        "userAgent": "stratus-red-team/1.0",
        "requestParameters": {"bucketName": "red-team-bucket"}
    }
    
    print("\n# Usage Example:")
    print("detector = CloudTrailThreatDetector()")
    print("detector.train(training_logs)")
    print("")
    
    # Test normal log
    is_threat = detector.predict(normal_log)
    result = detector.predict_with_confidence(normal_log)
    print(f"# Normal S3 access")
    print(f"is_threat = detector.predict(normal_log)")
    print(f"# Result: {is_threat}")
    print(f"result = detector.predict_with_confidence(normal_log)")
    print(f"# Result: {result}")
    print("")
    
    # Test threat log
    is_threat = detector.predict(threat_log)
    result = detector.predict_with_confidence(threat_log)
    print(f"# Red Team tool usage")
    print(f"is_threat = detector.predict(threat_log)")
    print(f"# Result: {is_threat}")
    print(f"result = detector.predict_with_confidence(threat_log)")
    print(f"# Result: {result}")


if __name__ == "__main__":
    print("CloudTrail Threat Detector - Test Suite")
    print("=" * 50)
    
    # Run all tests
    test_feature_extraction()
    detector = test_prediction_performance()
    test_model_persistence()
    demo_usage()
    
    print("\n=== Test Suite Completed ===")