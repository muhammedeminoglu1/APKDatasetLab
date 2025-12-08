"""
Data Normalizer - Normalize extracted features for ML
"""
from typing import Dict, List
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler


class DataNormalizer:
    """Normalize and transform feature data"""

    def __init__(self):
        self.scaler = None
        self.normalization_method = 'none'

    def normalize_dataset(self, df: pd.DataFrame, method='standard', exclude_columns=None) -> pd.DataFrame:
        """
        Normalize dataset using specified method

        Args:
            df: DataFrame with features
            method: 'standard', 'minmax', or 'none'
            exclude_columns: List of columns to exclude from normalization (e.g., labels, filenames)

        Returns:
            Normalized DataFrame
        """
        if method == 'none':
            return df

        if exclude_columns is None:
            exclude_columns = ['filename', 'label', 'package_name']

        # Select only numeric columns
        numeric_columns = df.select_dtypes(include=['int64', 'float64', 'bool']).columns
        columns_to_normalize = [col for col in numeric_columns if col not in exclude_columns]

        # Create copy to avoid modifying original
        df_normalized = df.copy()

        if len(columns_to_normalize) == 0:
            return df_normalized

        # Apply normalization
        if method == 'standard':
            self.scaler = StandardScaler()
            self.normalization_method = 'standard'
        elif method == 'minmax':
            self.scaler = MinMaxScaler()
            self.normalization_method = 'minmax'
        else:
            return df_normalized

        # Normalize selected columns
        df_normalized[columns_to_normalize] = self.scaler.fit_transform(df[columns_to_normalize])

        return df_normalized

    def convert_booleans_to_binary(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert boolean columns to 0/1"""
        df_copy = df.copy()
        bool_columns = df_copy.select_dtypes(include=['bool']).columns
        for col in bool_columns:
            df_copy[col] = df_copy[col].astype(int)
        return df_copy

    def fill_missing_values(self, df: pd.DataFrame, strategy='zero') -> pd.DataFrame:
        """Fill missing values in dataset"""
        df_copy = df.copy()

        if strategy == 'zero':
            df_copy = df_copy.fillna(0)
        elif strategy == 'mean':
            numeric_columns = df_copy.select_dtypes(include=['int64', 'float64']).columns
            df_copy[numeric_columns] = df_copy[numeric_columns].fillna(df_copy[numeric_columns].mean())
        elif strategy == 'median':
            numeric_columns = df_copy.select_dtypes(include=['int64', 'float64']).columns
            df_copy[numeric_columns] = df_copy[numeric_columns].fillna(df_copy[numeric_columns].median())

        return df_copy
