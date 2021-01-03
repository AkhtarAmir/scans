const expect = require('chai').expect;
var eksFailedClusters = require('./eksFailedClusters');

const listClusters = ["testCluster"];

const createCache = (listClusters, describeCluster, listClustersErr, describeClusterErr) => {
    var clusterName = (listClusters && listClusters.length) ? listClusters : null;
    return {
        eks: {
            listClusters: {
                'us-east-1': {
                    err: listClustersErr,
                    data: listClusters
                }
            },
            describeCluster: {
                'us-east-1': {
                    [clusterName]: {
                        err: describeClusterErr,
                        data: describeCluster
                    }
                }
            }
        }
    };
};

const describeCluster = [
    {
        "cluster": {
            "name": "testCluster",
            "arn": "arn:aws:eks:us-east-1:111122223333:cluster/testCluster",
            "createdAt": "2021-01-03T10:27:15.465000+05:00",
            "version": "1.18",
            "endpoint": "https://7B6A6E13725975070CB0E8BB61DDF549.gr7.us-east-1.eks.amazonaws.com",
            "roleArn": "arn:aws:iam::111122223333:role/eks-cluster-role",
            "resourcesVpcConfig": {
                "subnetIds": [
                    "subnet-c21b84cc",
                    "subnet-06aa0f60"
                ],
                "securityGroupIds": [],
                "clusterSecurityGroupId": "sg-016deda989149daf8",
                "vpcId": "vpc-99de2fe4",
                "endpointPublicAccess": true,
                "endpointPrivateAccess": false,
                "publicAccessCidrs": [
                    "0.0.0.0/0"
                ]
            },
            "kubernetesNetworkConfig": {
                "serviceIpv4Cidr": "10.100.0.0/16"
            },
            "logging": {
                "clusterLogging": [
                    {
                        "types": [
                            "api",
                            "audit",
                            "authenticator",
                            "controllerManager",
                            "scheduler"
                        ],
                        "enabled": false
                    }
                ]
            },
            "identity": {
                "oidc": {
                    "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/7B6A6E13725975070CB0E8BB61DDF549"
                }
            },
            "status": "ACTIVE",
            "certificateAuthority": {
                "data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJeE1ERXdNekExTXpZME5Wb1hEVE14TURFd01UQTFNelkwTlZvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTThKCkZlbzMwajNwWlUyZk14aWVjWkJJbXFINW9xVFRmSTQycGZ1VUdsY3RWQWM1VjR2cVV0bHREa3dtN2tVbWNVaXQKVjNTY0hiR29Dbk80b2VITzJYQ0tlS0lnNU1WeXUwclhmSDFlTFpCajJpZG0wOVJJRnZkaXV6UmRQWHV5VkMrYQpFSElUZ1VrSmxxcUJSWGM1MGpjU0dxc3RxNitwUTVsRzFzcm5hYWQxaW8xZTVHYlc2bEFibnVaa1Z3by9VWHFqCkIzR29iQ1phb2FHUGZ4Y1g5cnpVc256REF5bnMzRFhSSUQ4ZnZYZHBHOVR0ZzFNOVJrd3N4dm4xNTVzR0hxSSsKMm9XWmpxMEMzK0JnZXA4cGFUWllENjZ0eGd0djlWUC9EMFpsbmRiSmlneEtEZG5SVXJlTTZoL2laaXBNOTIrMgpUcEw0VTVzOUN4NmpMMURpNkY4Q0F3RUFBYU1qTUNFd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFBbi9LeURGdjhmMzIwbjAvZDF5eVNqWUFzR3MKZVI4L3g5UWk1bVdaVUt3MlVjU29Ibjd5T29GaFNKNldMaWtka1ZLdmZERGcxZUhDL3Njak9maDJjNS9NNzByTQordCtFeGliMlVtNVhoRmZpSUNBUGs1L0k1cFUvRDFLYURTUzQ2cERER0l3TkRqNHlKcWRaSHVtcXlyaHVvWFJpClA4d25SMTJFSWUzWHRLOFZLeEZadWlrMHA2SVZ2c0RITW5GMUtSS2dSVDJGVDFkTzZnZ1MrSG1LRjdIajlZRXgKRmxzOUZnZWU1bkF1dVVpalY2azNQRXQrZVZPbWRxT3dDbFhQR0NTZEdJcmpaVHh1SEtBbDlCY2oxeTNIdEE5KwptcFN4ZjgwK2RUR2lpcmd0U1JUQiszV2tCVlVsbkpuc0RGNzl1eW01bmw4cThvK1ZWeFh3b0pCbE9HZz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
            },
            "platformVersion": "eks.3",
            "tags": {}
        }
    },
    {
        "cluster": {
            "name": "testCluster",
            "arn": "arn:aws:eks:us-east-1:111122223333:cluster/testCluster",
            "createdAt": "2021-01-03T10:27:15.465000+05:00",
            "version": "1.18",
            "endpoint": "https://7B6A6E13725975070CB0E8BB61DDF549.gr7.us-east-1.eks.amazonaws.com",
            "roleArn": "arn:aws:iam::111122223333:role/eks-cluster-role",
            "resourcesVpcConfig": {
                "subnetIds": [
                    "subnet-c21b84cc",
                    "subnet-06aa0f60"
                ],
                "securityGroupIds": [],
                "clusterSecurityGroupId": "sg-016deda989149daf8",
                "vpcId": "vpc-99de2fe4",
                "endpointPublicAccess": true,
                "endpointPrivateAccess": false,
                "publicAccessCidrs": [
                    "0.0.0.0/0"
                ]
            },
            "kubernetesNetworkConfig": {
                "serviceIpv4Cidr": "10.100.0.0/16"
            },
            "logging": {
                "clusterLogging": [
                    {
                        "types": [
                            "api",
                            "audit",
                            "authenticator",
                            "controllerManager",
                            "scheduler"
                        ],
                        "enabled": false
                    }
                ]
            },
            "identity": {
                "oidc": {
                    "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/7B6A6E13725975070CB0E8BB61DDF549"
                }
            },
            "status": "FAILED",
            "certificateAuthority": {
                "data": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJeE1ERXdNekExTXpZME5Wb1hEVE14TURFd01UQTFNelkwTlZvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTThKCkZlbzMwajNwWlUyZk14aWVjWkJJbXFINW9xVFRmSTQycGZ1VUdsY3RWQWM1VjR2cVV0bHREa3dtN2tVbWNVaXQKVjNTY0hiR29Dbk80b2VITzJYQ0tlS0lnNU1WeXUwclhmSDFlTFpCajJpZG0wOVJJRnZkaXV6UmRQWHV5VkMrYQpFSElUZ1VrSmxxcUJSWGM1MGpjU0dxc3RxNitwUTVsRzFzcm5hYWQxaW8xZTVHYlc2bEFibnVaa1Z3by9VWHFqCkIzR29iQ1phb2FHUGZ4Y1g5cnpVc256REF5bnMzRFhSSUQ4ZnZYZHBHOVR0ZzFNOVJrd3N4dm4xNTVzR0hxSSsKMm9XWmpxMEMzK0JnZXA4cGFUWllENjZ0eGd0djlWUC9EMFpsbmRiSmlneEtEZG5SVXJlTTZoL2laaXBNOTIrMgpUcEw0VTVzOUN4NmpMMURpNkY4Q0F3RUFBYU1qTUNFd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFBbi9LeURGdjhmMzIwbjAvZDF5eVNqWUFzR3MKZVI4L3g5UWk1bVdaVUt3MlVjU29Ibjd5T29GaFNKNldMaWtka1ZLdmZERGcxZUhDL3Njak9maDJjNS9NNzByTQordCtFeGliMlVtNVhoRmZpSUNBUGs1L0k1cFUvRDFLYURTUzQ2cERER0l3TkRqNHlKcWRaSHVtcXlyaHVvWFJpClA4d25SMTJFSWUzWHRLOFZLeEZadWlrMHA2SVZ2c0RITW5GMUtSS2dSVDJGVDFkTzZnZ1MrSG1LRjdIajlZRXgKRmxzOUZnZWU1bkF1dVVpalY2azNQRXQrZVZPbWRxT3dDbFhQR0NTZEdJcmpaVHh1SEtBbDlCY2oxeTNIdEE5KwptcFN4ZjgwK2RUR2lpcmd0U1JUQiszV2tCVlVsbkpuc0RGNzl1eW01bmw4cThvK1ZWeFh3b0pCbE9HZz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
            },
            "platformVersion": "eks.3",
            "tags": {}
        }
    }
];

const createNullCache = () => {
    return {
        lambda: {
            listClusters: {
                'us-east-1': null
            }
        }
    };
};

describe('eksFailedClusters', function () {
    describe('run', function () {
        it('should PASS if EKS cluster is not in failed state', function (done) {
            const cache = createCache(listClusters, describeCluster[0], null, null);
            eksFailedClusters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if EKS cluster is in failed state', function (done) {
            const cache = createCache(listClusters, describeCluster[1], null, null);
            eksFailedClusters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if No EKS clusters found', function (done) {
            const cache = createCache([], null, null, null);
            eksFailedClusters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list EKS clusters', function (done) {
            const cache = createCache(listClusters, describeCluster[1], {message: 'unable to list EKS clusters'}, null);
            eksFailedClusters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe EKS cluster', function (done) {
            const cache = createCache(listClusters, describeCluster[1], null, {message: 'unable to describe EKS cluster'});
            eksFailedClusters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list EKS clusters response is not found', function (done) {
            const cache = createNullCache();
            eksFailedClusters.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
