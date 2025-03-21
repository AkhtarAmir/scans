var expect = require('chai').expect;
var accessAnalyzerActiveFindings = require('./accessAnalyzerActiveFindings');

const listAnalyzers = [
    {
        "arn": "arn:aws:access-analyzer:us-east-1:000011112222:analyzer/ConsoleAnalyzer-c1a86385-8c13-42cd-96bf-31b10d2050ca",
        "createdAt": "2022-01-12T13:43:05+00:00",
        "lastResourceAnalyzed": "arn:aws:sqs:us-east-1:000011112222:akhtarqueue",
        "lastResourceAnalyzedAt": "2022-01-12T13:43:05.455000+00:00",
        "name": "ConsoleAnalyzer-c1a86385-8c13-42cd-96bf-31b10d2050ca",
        "status": "ACTIVE",
        "tags": {},
        "type": "ACCOUNT"
    }
];

const listFindings = [
{
    "findings": [
            {
                "action": [
                    "kms:RetireGrant"
                ],
                "analyzedAt": "2022-01-12T13:43:05.433000+00:00",
                "condition": {},
                "createdAt": "2022-01-12T13:43:05.433000+00:00",
                "id": "084f6bb6-a331-4c2d-87db-b2f595947ba0",
                "isPublic": false,
                "principal": {
                    "AWS": "108297888182"
                },
                "resource": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
                "resourceOwnerAccount": "000011112222",
                "resourceType": "AWS::KMS::Key",
                "status": "ACTIVE",
                "updatedAt": "2022-01-12T13:43:05.433000+00:00"
            },
            {
                "action": [
                    "kms:Decrypt",
                    "kms:Encrypt"
                ],
                "analyzedAt": "2022-01-12T13:43:05.433000+00:00",
                "condition": {},
                "createdAt": "2022-01-12T13:43:05.433000+00:00",
                "id": "ca358041-0222-4493-8288-e5f5f0c77d19",
                "isPublic": false,
                "principal": {
                    "AWS": "560213429563"
                },
                "resource": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
                "resourceOwnerAccount": "000011112222",
                "resourceType": "AWS::KMS::Key",
                "status": "ARCHIVED",
                "updatedAt": "2022-01-12T13:48:20+00:00"
            },
            {
                "action": [
                    "kms:Decrypt",
                    "kms:Encrypt"
                ],
                "analyzedAt": "2022-01-12T13:43:05.433000+00:00",
                "condition": {},
                "createdAt": "2022-01-12T13:43:05.433000+00:00",
                "id": "ca358041-0222-4493-8288-e5f5f0c77d19",
                "isPublic": false,
                "principal": {
                    "AWS": "560213429563"
                },
                "resource": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
                "resourceOwnerAccount": "000011112222",
                "resourceType": "AWS::KMS::Key",
                "status": "RESOLVED",
                "updatedAt": "2022-01-12T13:48:20+00:00"
            }
        ]
},
{
    "findings": [
            {
                "action": [
                    "kms:RetireGrant"
                ],
                "analyzedAt": "2022-01-12T13:43:05.433000+00:00",
                "condition": {},
                "createdAt": "2022-01-12T13:43:05.433000+00:00",
                "id": "084f6bb6-a331-4c2d-87db-b2f595947ba0",
                "isPublic": false,
                "principal": {
                    "AWS": "108297888182"
                },
                "resource": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
                "resourceOwnerAccount": "000011112222",
                "resourceType": "AWS::KMS::Key",
                "status": "ARCHIVED",
                "updatedAt": "2022-01-12T13:43:05.433000+00:00"
            },
            {
                "action": [
                    "kms:Decrypt",
                    "kms:Encrypt"
                ],
                "analyzedAt": "2022-01-12T13:43:05.433000+00:00",
                "condition": {},
                "createdAt": "2022-01-12T13:43:05.433000+00:00",
                "id": "ca358041-0222-4493-8288-e5f5f0c77d19",
                "isPublic": false,
                "principal": {
                    "AWS": "560213429563"
                },
                "resource": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
                "resourceOwnerAccount": "000011112222",
                "resourceType": "AWS::KMS::Key",
                "status": "ARCHIVED",
                "updatedAt": "2022-01-12T13:48:20+00:00"
            },
            {
                "action": [
                    "kms:Decrypt",
                    "kms:Encrypt"
                ],
                "analyzedAt": "2022-01-12T13:43:05.433000+00:00",
                "condition": {},
                "createdAt": "2022-01-12T13:43:05.433000+00:00",
                "id": "ca358041-0222-4493-8288-e5f5f0c77d19",
                "isPublic": false,
                "principal": {
                    "AWS": "560213429563"
                },
                "resource": "arn:aws:kms:us-east-1:000011112222:key/fb8ab834-47f3-4434-810a-e9cb1634de69",
                "resourceOwnerAccount": "000011112222",
                "resourceType": "AWS::KMS::Key",
                "status": "RESOLVED",
                "updatedAt": "2022-01-12T13:48:20+00:00"
            }
        ]
}
        
];

const listFindingsV2 = [
{
    "findings": [
            {
                "analyzedAt": "2025-01-23T13:06:24+00:00",
                "createdAt": "2025-01-23T13:06:56+00:00",
                "id": "1a234567-bc6d-7yui-h5j7-4f5f9j8987y0",
                "resource": "arn:aws:iam::123456789123:role/abcd-abcd-adfitoui-abcdefg-p1-AsdfghTfjdudnjkDkjg-Z9JgMyMzcxOZ",
                "resourceType": "AWS::IAM::Role",
                "resourceOwnerAccount": "123456789123",
                "status": "ACTIVE",
                "updatedAt": "2025-01-23T13:06:56+00:00",
                "findingType": "UnusedIAMRole"
            },
            {
                "analyzedAt": "2025-01-23T13:06:24+00:00",
                "createdAt": "2025-01-23T13:06:56+00:00",
                "id": "938r4848-4h4j-8449-76d8-8768dh5dhh4u",
                "resource": "arn:aws:iam::123456789123:role/abcd-abcd-adfitoui-abcdefg-AsdfghTfjdudnjkDkjg-6vzrTVSqTaNe",
                "resourceType": "AWS::IAM::Role",
                "resourceOwnerAccount": "123456789123",
                "status": "ACTIVE",
                "updatedAt": "2025-01-23T13:06:56+00:00",
                "findingType": "UnusedIAMRole"
            },
            {
                "analyzedAt": "2025-01-23T13:06:55+00:00",
                "createdAt": "2025-01-23T13:06:56+00:00",
                "id": "7484f848-984j-498l-784s-yryh74748f45",
                "resource": "arn:aws:iam::123456789123:role/service-role/sdfghyFj-FGH-njkkjg-plgd-6uhjn9ok",
                "resourceType": "AWS::IAM::Role",
                "resourceOwnerAccount": "123456789123",
                "status": "ACTIVE",
                "updatedAt": "2025-01-23T13:06:56+00:00",
                "findingType": "UnusedPermission"
            },
        ]
},
{
    "findings": [
            {
                "analyzedAt": "2025-01-23T13:06:24+00:00",
                "createdAt": "2025-01-23T13:06:56+00:00",
                "id": "1a234567-bc6d-7yui-h5j7-4f5f9j8987y0",
                "resource": "arn:aws:iam::123456789123:role/abcd-abcd-adfitoui-abcdefg-p1-AsdfghTfjdudnjkDkjg-Z9JgMyMzcxOZ",
                "resourceType": "AWS::IAM::Role",
                "resourceOwnerAccount": "123456789123",
                "status": "ARCHIVED",
                "updatedAt": "2025-01-23T13:06:56+00:00",
                "findingType": "UnusedIAMRole"
            },
            {
                "analyzedAt": "2025-01-23T13:06:24+00:00",
                "createdAt": "2025-01-23T13:06:56+00:00",
                "id": "938r4848-4h4j-8449-76d8-8768dh5dhh4u",
                "resource": "arn:aws:iam::123456789123:role/abcd-abcd-adfitoui-abcdefg-AsdfghTfjdudnjkDkjg-6vzrTVSqTaNe",
                "resourceType": "AWS::IAM::Role",
                "resourceOwnerAccount": "123456789123",
                "status": "ARCHIVED",
                "updatedAt": "2025-01-23T13:06:56+00:00",
                "findingType": "UnusedIAMRole"
            },
            {
                "analyzedAt": "2025-01-23T13:06:55+00:00",
                "createdAt": "2025-01-23T13:06:56+00:00",
                "id": "7484f848-984j-498l-784s-yryh74748f45",
                "resource": "arn:aws:iam::123456789123:role/service-role/sdfghyFj-FGH-njkkjg-plgd-6uhjn9ok",
                "resourceType": "AWS::IAM::Role",
                "resourceOwnerAccount": "123456789123",
                "status": "RESOLVED",
                "updatedAt": "2025-01-23T13:06:56+00:00",
                "findingType": "UnusedPermission"
            },
        ]
}

]

const createCache = (analyzer, listFindings, analyzerErr, listFindingsErr) => {
    var analyzerArn = (analyzer && analyzer.length) ? analyzer[0].arn: null;
    return {
        accessanalyzer: {
            listAnalyzers: {
                'us-east-1': {
                    err: analyzerErr,
                    data: analyzer
                },
            },
            listFindings: {
                'us-east-1': {
                    [analyzerArn]: {
                        data:listFindings,
                        err: listFindingsErr
                    }
                }
            }
        },
    };
};

describe('accessAnalyzerActiveFindings', function () {
    describe('run', function () {
        it('should FAIL if Amazon IAM access analyzer V1 has active findings.', function (done) {
            const cache = createCache(listAnalyzers, listFindings[0]);
            accessAnalyzerActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Amazon IAM Access Analyzer has active findings');
                done();
            });
        });

        it('should FAIL if Amazon IAM access analyzer v2 has active findings.', function (done) {
            const cache = createCache(listAnalyzers, listFindingsV2[0]);
            accessAnalyzerActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Amazon IAM Access Analyzer has active findings');
                done();
            });
        });

        it('should PASS if Amazon IAM access analyzer V1 have no active findings.', function (done) {
            const cache = createCache(listAnalyzers, listFindings[1]);
            accessAnalyzerActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Amazon IAM Access Analyzer has no active findings');
                
                done();
            });
        });


        it('should PASS if Amazon IAM access analyzer V2 have no active findings.', function (done) {
            const cache = createCache(listAnalyzers, listFindingsV2[1]);
            accessAnalyzerActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Amazon IAM Access Analyzer has no active findings');
                
                done();
            });
        });

        it('should PASS if no analyzers found', function (done) {
            const cache = createCache([]);
            accessAnalyzerActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No IAM Access Analyzer analyzers found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for IAM access analyzers', function (done) {
            const cache = createCache(null, null, { message: "Unable to query for IAM access analyzers" });
            accessAnalyzerActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for IAM Access Analyzer analyzers');
                done();
            });
        });
    });
})