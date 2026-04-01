/*
 * Ant Group
 * Copyright (c) 2004-2026 All Rights Reserved.
 */
package com.hoperun.datax.transfer.sm4;

import com.alibaba.datax.common.element.Column;
import com.alibaba.datax.common.element.Record;
import com.alibaba.datax.common.element.StringColumn;
import com.alibaba.datax.common.exception.DataXException;
import com.alibaba.datax.core.transport.transformer.TransformerErrorCode;
import com.alibaba.datax.transformer.Transformer;
import com.alibaba.fastjson2.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class SM4EncryptTransformer extends Transformer {
    private static final Logger LOG = LoggerFactory.getLogger(SM4EncryptTransformer.class);

    private int[]  columnIndexes;
    private String encryptKey;

    public SM4EncryptTransformer() {
        setTransformerName("sM4EncryptTransformer");
    }

    /**
     * 方法1：使用 paras 参数初始化（传统方式）
     */
    @Override
    public Record evaluate(Record record, Object... paras) {
        if (columnIndexes == null) {
            init(paras);
        }

        return processRecord(record);
    }

    private Record processRecord(Record record) {
        for (int idx : columnIndexes) {
            if (idx >= record.getColumnNumber()) {
                LOG.warn("Column index {} exceeds record column number {}", idx, record.getColumnNumber());
                continue;
            }

            Column column = record.getColumn(idx);
            if (column == null || column.getRawData() == null) {
                continue;
            }

            String originalValue = column.asString();
            if (originalValue != null && !originalValue.isEmpty()) {
                try {
                    String encryptedValue = GtxtSM4BCUtil.encryptEcb(originalValue, encryptKey);
                    record.setColumn(idx, new StringColumn(encryptedValue));
                } catch (Exception e) {
                    LOG.error("Failed to encrypt column {} with value {}",
                            idx, maskSensitiveData(originalValue), e);
                    throw DataXException.asDataXException(
                            TransformerErrorCode.TRANSFORMER_RUN_EXCEPTION,
                            "SM4 encryption failed for column " + idx, e
                    );
                }
            }
        }

        return record;
    }

    private void init(Object... paras) {
        LOG.info("SM4EncryptTransformer initialized with parameters: {}", Arrays.toString(paras));
        if (paras.length == 1 && paras[0] instanceof JSONObject) {
            // 对象形式
            JSONObject param = (JSONObject) paras[0];
            String columnStr = param.getString("columnIndexes");
            this.encryptKey = param.getString("key");
            parseColumnIndexes(columnStr);
            LOG.info("SM4EncryptTransformer initialized, columns: {}, key length: {}",
                    columnStr, encryptKey.length());
        } else if (paras.length >= 2) {
            // 数组形式
            String columnStr = (String) paras[1];
            this.encryptKey = (String) paras[2];
            parseColumnIndexes(columnStr);
            LOG.info("SM4EncryptTransformer initialized, columns: {}, key length: {}",
                    columnStr, encryptKey.length());
        } else {
            throw DataXException.asDataXException(
                    TransformerErrorCode.TRANSFORMER_ILLEGAL_PARAMETER,
                    "Invalid parameter format"
            );
        }

    }

    private void parseColumnIndexes(String columnStr) {
        if (columnStr == null || columnStr.trim().isEmpty()) {
            throw DataXException.asDataXException(
                    TransformerErrorCode.TRANSFORMER_ILLEGAL_PARAMETER,
                    "columnIndexes cannot be empty"
            );
        }
        this.columnIndexes = Arrays.stream(columnStr.split(","))
                .map(String::trim)
                .mapToInt(Integer::parseInt)
                .toArray();
        LOG.info("SM4EncryptTransformer initialized with columnIndexes: {}", Arrays.toString(columnIndexes));
    }

    private String maskSensitiveData(String data) {
        if (data == null || data.length() <= 4) {
            return "***";
        }
        return data.substring(0, 2) + "****" + data.substring(data.length() - 2);
    }
}
